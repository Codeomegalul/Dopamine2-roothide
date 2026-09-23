// language: Objective-C (ARC), file: BaseBin/watchdogfix/src/main.m
// target: watchdogd, iOS 16.7.16 (20H392, iPhone10,3) — лечение «залипания» учёта
// чек-инов, из-за которого watchdogd повторно заказывает userspace-панику
// «no successful checkins from %s in %llu seconds» и Dopamine уходит в userspace-reboot.
//
// Что делает компонент (две половины, обе — внутри адресного пространства watchdogd):
//   1) каждые 2 с обходит таблицу сервисов watchdogd и у записи с накопленными раундами
//      без успеха (или с «чужим» reply-портом) сбрасывает mach-порт сервиса
//      [svc+0x58] = MACH_PORT_NULL, чтобы проход late-discovery (0x1000094e0 требует
//      [+0x58]==0) снова вызвал bootstrap_look_up и переоткрыл порт. Записи с
//      [+0x2d]==1 (logd и прочие «skip crashing») не трогаются никогда.
//   2) один раз при загрузке снимает отбрасывание «поздних» ответов: инструкция
//      b.ne на 0x1000099c4 («...doesn't match receive port, skipping message»)
//      заменяется на nop, после чего ответ демона с несовпавшим receive-портом
//      раунда идёт по штатной ветке приёма (0x1000099c4..), пишет [+0xa8]/[+0xa9],
//      и штатный учёт раунда (0x100008358 → 0x100008360…0x100008384) сам обновляет
//      время успеха [+0x78] и обнуляет счётчик неуспехов [+0x9c].
//
// Чего компонент НЕ делает: не перехватывает selector==2 (паника остаётся у
// watchdoghook.dylib), не трогает kext, не глушит userspace-мониторинг селекторами
// 3/4, не перезапускает watchdogd и не правит больше ни одной инструкции.
//
// ВСЕ адреса и смещения ниже — от билда 20H392 (watchdogd 152816 Б,
// SHA-256 7951d706…4b1e1). На другом билде iOS их надо снимать заново
// (дизасм и карта обращений — ~/watchdog_re, разбор — checkin_rootcause.md §7.1).
// ДОПУЩЕНИЕ: таблица ищется по сигнатуре (имена сервисов + совпадение счётчика за
// таблицей) и уточняется по числу ссылок из __text, поэтому смена адреса таблицы
// между сборками сама по себе патч не ломает — ломает только смена формата записи.

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/getsect.h>
#import <dispatch/dispatch.h>
#import <os/log.h>
#include <libkern/OSCacheControl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

// ─────────────────────────── 20H392: адреса ───────────────────────────
#define WDF_ENTRY_SIZE          0x6f8ull     // размер записи сервиса (madd x8, idx, #0x6f8)
#define WDF_TABLE_VADDR         0x100015718ull // таблица 14 сервисов, __DATA,__data
#define WDF_COUNT_VADDR         0x10001b8a8ull // счётчик сервисов (=14) == table+14*0x6f8
#define WDF_THRESHOLD_VADDR     0x10001b8acull // порог раундов без успеха (=2)
#define WDF_REPLY_ID            0x005bb0a8u    // msgh_id ответа (константа @0x100010aa8)
#define WDF_REPLY_ID_MIN        0x005bb000u    // нижняя граница диапазона id (0x10000aee0)
#define WDF_MISMATCH_INSN_VA    0x1000099c4ull // b.ne -> «skipping message» (точка отбрасывания)
#define WDF_MISMATCH_INSN       0x54000801u    // ожидаемая кодировка b.ne в 20H392
#define WDF_REPLY_HANDLER_VA    0x100009974ull // обработчик приёма ответа (для санити-чека)
#define WDF_ROUND_NS            10000000000ull // раунд 10 с (dispatch_time(NOW,0x2540BE400) @0x10000810c)
#define WDF_NOP                 0xd503201fu

// ─────────────────────────── 20H392: смещения записи ───────────────────────────
#define OFF_BUNDLE_ID           0x08   // const char *bundle id          (com.apple.backboardd)
#define OFF_MACH_NAME           0x10   // const char *mach-имя пинга     (com.apple.backboard.oswatchdog)
#define OFF_SHORT_NAME          0x18   // const char *короткое имя       (backboardd)
#define OFF_LABEL               0x20   // const char *label для PID-запросов
#define OFF_LATE_CHECKIN        0x2c   // u8, 1 у remoted/automationdevicemonitoringd
#define OFF_SKIP_CRASH          0x2d   // u8, 1 ТОЛЬКО у logd — «skip crashing»
#define OFF_TYPE                0x30   // u32: 1 обычный, 2 backboardd, 3 контроллер
#define OFF_PORT                0x58   // mach_port_t сервиса из bootstrap_look_up (записи нуля в бинаре НЕТ)
#define OFF_MONITOR_START       0x60   // u64, нс CLOCK_UPTIME_RAW, «мониторинг включён»
#define OFF_SUCCESS_COUNT       0x70   // u64, счётчик успешных чек-инов (++ @0x10000837c)
#define OFF_LAST_SUCCESS        0x78   // u64, время последнего УСПЕХА (единственная запись @0x100008360)
#define OFF_LAST_SUCCESS_ROUND  0x80   // u64, номер раунда успеха
#define OFF_LAST_REPLY_TS       0x88   // u64, время последнего разобранного ответа
#define OFF_LAST_REPLY_ROUND    0x90   // u64, номер раунда последнего ответа
#define OFF_STRIKES             0x9c   // u32, раундов без успеха (порог 0x10001b8ac = 2)
#define OFF_REPLY_PORT          0xa0   // u32, reply-порт ТЕКУЩЕГО раунда (сверка @0x1000099bc)
#define OFF_SEND_RC             0xa4   // u32, код возврата отправки пинга
#define OFF_REPLY_SEEN          0xa8   // u8, ответ за раунд получен
#define OFF_ALIVE_FLAG          0xa9   // u8, is_alive последнего ответа (читается @0x100008354)

#define WDF_MAX_SVC             32
#define WDF_TICK_NS             (2ull * NSEC_PER_SEC)   // «раз в 2 с»
#define WDF_MAX_HEALS_PER_EPOCH 3                       // столько подряд «расшевеливаний» без успеха
#define WDF_BACKOFF_NS          (60ull * NSEC_PER_SEC)  // и запись на паузу — паника снова доходит до watchdoghook
#define WDF_DISABLE_PATH        "/var/log/.disable_watchdogfix" // ручной тормоз, как у watchdoghook

// Короткие имена из таблицы watchdogd 20H392 (порядок = порядок записей).
static const char *kWdfKnownNames[] = {
    "backboardd", "PreboardService", "SpringBoard", "CarPlay", "hidd.nonui",
    "mediaserverd", "darwinaudiod", "remoted", "logd", "thermalmonitord",
    "runningboardd", "wifid", "configd", "automationdevicemonitoringd",
};
static const uint32_t kWdfKnownCount = sizeof(kWdfKnownNames) / sizeof(kWdfKnownNames[0]);

typedef struct {
    uint64_t start;
    uint64_t end;
} wdf_range_t;

typedef struct {
    uint8_t *entry;                 // указатель на запись в адресном пространстве watchdogd
    char     name[64];              // короткое имя (копия строки по +0x18)
    uint32_t type;                  // [+0x30]
    uint32_t heals;                 // «расшевеливаний» подряд без наблюдённого успеха
    uint64_t heal_until;            // нс uptime, до которого запись не трогаем (backoff)
    uint64_t seen_success_count;    // [+0x70] на прошлом тике — детект восстановления
    uint64_t seen_last_success;     // [+0x78] на прошлом тике
    int      revive_armed;          // для obl1_wd_fix_revived()
    uint64_t revive_base_count;     // [+0x70] в момент реанимации
    uint64_t revive_base_ts;        // [+0x78] в момент реанимации
    int      shared_reply_logged;   // чтобы не спамить про «чужой» reply-порт
} wdf_svc_t;

static wdf_svc_t g_svcs[WDF_MAX_SVC];
static uint32_t  g_count;
static uint8_t  *g_table;
static const struct mach_header_64 *g_mh;
static intptr_t  g_slide;
static wdf_range_t g_ranges[32];
static uint32_t  g_nranges;
static wdf_range_t g_texts[8];
static uint32_t  g_ntexts;
static int       g_located;
static int       g_patched;
static dispatch_source_t g_timer;

// ─────────────────────────── журнал ───────────────────────────
static void wdf_log(const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    // os_log: строки видны как процесс watchdogd
    // (log show --last 5m --predicate 'process == "watchdogd"' | grep watchdogfix)
    os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_DEFAULT, "watchdogfix: %{public}s", buf);
}

// ─────────────────────────── безопасное чтение/запись чужого образа ───────────────────────────
static int wdf_mapped(const void *p, size_t len)
{
    uint64_t a = (uint64_t)p;
    if (!a) return 0;
    for (uint32_t i = 0; i < g_nranges; i++) {
        if (a >= g_ranges[i].start && a + len <= g_ranges[i].end) return 1;
    }
    return 0;
}

static uint64_t wdf_rd64(const void *p)
{
    uint64_t v = 0;
    if (wdf_mapped(p, sizeof(v))) memcpy(&v, p, sizeof(v));
    return v;
}

static uint32_t wdf_rd32(const void *p)
{
    uint32_t v = 0;
    if (wdf_mapped(p, sizeof(v))) memcpy(&v, p, sizeof(v));
    return v;
}

static uint8_t wdf_rd8(const void *p)
{
    uint8_t v = 0;
    if (wdf_mapped(p, sizeof(v))) memcpy(&v, p, sizeof(v));
    return v;
}

static void wdf_wr32(void *p, uint32_t v)
{
    if (wdf_mapped(p, sizeof(v))) memcpy(p, &v, sizeof(v));
}

// C-строка внутри образа watchdogd; возвращает длину или 0
static size_t wdf_cstr(const char *p, char *out, size_t outsz)
{
    if (!p || !wdf_mapped(p, 1) || outsz < 2) return 0;
    size_t n = 0;
    while (n + 1 < outsz) {
        if (!wdf_mapped(p + n, 1)) break;
        unsigned char c = (unsigned char)p[n];
        if (c == 0) break;
        if (c < 0x20 || c > 0x7e) return 0;   // имена сервисов — ASCII
        out[n] = (char)c;
        n++;
    }
    out[n] = 0;
    return n;
}

static int wdf_name_known(const char *name)
{
    for (uint32_t i = 0; i < kWdfKnownCount; i++) {
        if (!strcmp(name, kWdfKnownNames[i])) return 1;
    }
    return 0;
}

// ─────────────────────────── образ watchdogd, сегменты, __text ───────────────────────────
static void wdf_image_init(void)
{
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        if (!strcmp(nm, "/usr/libexec/watchdogd") || !strcmp(nm, "/private/usr/libexec/watchdogd")) {
            g_mh = (const struct mach_header_64 *)_dyld_get_image_header(i);
            g_slide = _dyld_get_image_vmaddr_slide(i);
            break;
        }
    }
    if (!g_mh) {
        // ДОПУЩЕНИЕ: dylib грузится только в watchdogd, поэтому главный образ — он же
        g_mh = (const struct mach_header_64 *)_dyld_get_image_header(0);
        g_slide = _dyld_get_image_vmaddr_slide(0);
    }
    if (!g_mh || g_mh->magic != MH_MAGIC_64) {
        g_mh = NULL;
        return;
    }

    const uint8_t *p = (const uint8_t *)g_mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < g_mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize < sizeof(struct load_command)) break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (seg->vmsize && (seg->initprot & VM_PROT_READ) && g_nranges < 32) {
                g_ranges[g_nranges].start = (uint64_t)(g_slide + (intptr_t)seg->vmaddr);
                g_ranges[g_nranges].end = g_ranges[g_nranges].start + seg->vmsize;
                g_nranges++;
            }
            const struct section_64 *sect = (const struct section_64 *)((const uint8_t *)seg + sizeof(*seg));
            for (uint32_t j = 0; j < seg->nsects; j++, sect++) {
                if (!strcmp(sect->sectname, "__text") && g_ntexts < 8) {
                    g_texts[g_ntexts].start = (uint64_t)(g_slide + (intptr_t)sect->addr);
                    g_texts[g_ntexts].end = g_texts[g_ntexts].start + sect->size;
                    g_ntexts++;
                }
            }
        }
        p += lc->cmdsize;
    }
}

// ─────────────────────────── поиск таблицы по сигнатуре ───────────────────────────
// Считаем ссылки из __text на кандидата (ADR / ADRP+ADD) — так живая таблица
// отличается от любого похожего массива данных.
static uint32_t wdf_code_refs(uint64_t target)
{
    uint32_t refs = 0;
    for (uint32_t t = 0; t < g_ntexts; t++) {
        for (uint64_t pc = g_texts[t].start; pc + 8 <= g_texts[t].end; pc += 4) {
            uint32_t i0 = wdf_rd32((const void *)pc);
            uint32_t i1 = wdf_rd32((const void *)(pc + 4));
            int64_t hit = 0;
            if ((i0 & 0x9f000000u) == 0x10000000u) {              // ADR
                int64_t imm = (int64_t)((((i0 >> 5) & 0x7ffff) << 2) | ((i0 >> 29) & 3));
                if (imm & (1 << 20)) imm -= (1 << 21);
                hit = ((int64_t)pc + imm) == (int64_t)target;
            } else if ((i0 & 0x9f000000u) == 0x90000000u) {       // ADRP
                int64_t imm = (int64_t)((((i0 >> 5) & 0x7ffff) << 2) | ((i0 >> 29) & 3));
                if (imm & (1 << 20)) imm -= (1 << 21);
                uint64_t page = (uint64_t)(((int64_t)pc & ~0xfffull) + (imm << 12));
                if ((i1 & 0xffc00000u) == 0x91000000u) {          // + ADD imm
                    uint32_t imm12 = (i1 >> 10) & 0xfff;
                    uint32_t sh = (i1 >> 22) & 1;
                    hit = (page + ((uint64_t)imm12 << (12 * sh))) == target;
                }
            }
            if (hit) refs++;
        }
    }
    return refs;
}

// Кандидат: >=4 записей подряд с известным коротким именем по +0x18 и счётчиком,
// равным числу записей, сразу за массивом (20H392: count @table+14*0x6f8).
static uint8_t *wdf_scan_table(void)
{
    uint8_t *best = NULL;
    uint32_t best_refs = 0;
    for (uint32_t r = 0; r < g_nranges; r++) {
        uint64_t a = (g_ranges[r].start + 7) & ~7ull;
        for (; a + 8 <= g_ranges[r].end; a += 8) {
            uint32_t n = 0;
            while (n < WDF_MAX_SVC) {
                char nm[64];
                uint64_t sp = wdf_rd64((const void *)(a + (uint64_t)n * WDF_ENTRY_SIZE + OFF_SHORT_NAME));
                if (!wdf_cstr((const char *)sp, nm, sizeof(nm))) break;
                if (!wdf_name_known(nm)) break;
                n++;
            }
            if (n < 4) continue;
            if (wdf_rd32((const void *)(a + (uint64_t)n * WDF_ENTRY_SIZE)) != n) continue;
            uint32_t refs = wdf_code_refs(a);
            if (refs > best_refs) {
                best_refs = refs;
                best = (uint8_t *)a;
            }
        }
    }
    if (best && best_refs >= 2) return best;
    // Фолбэк: адрес 20H392 + slide, если сигнатура не сложилась (напр. изменённый список имён)
    uint8_t *fixed = (uint8_t *)(g_slide + (intptr_t)WDF_TABLE_VADDR);
    uint32_t cnt = wdf_rd32(fixed + 14 * WDF_ENTRY_SIZE);
    if (wdf_mapped(fixed, WDF_ENTRY_SIZE) && cnt >= 4 && cnt <= WDF_MAX_SVC) return fixed;
    return NULL;
}

static int wdf_locate_table(void)
{
    if (g_located && g_table) return 1;
    if (!g_mh) wdf_image_init();
    if (!g_mh) return 0;
    uint8_t *tbl = wdf_scan_table();
    if (!tbl) return 0;

    uint32_t count = 0;
    for (uint32_t n = 0; n < WDF_MAX_SVC; n++) {
        char nm[64];
        uint64_t sp = wdf_rd64(tbl + (uint64_t)n * WDF_ENTRY_SIZE + OFF_SHORT_NAME);
        if (!wdf_cstr((const char *)sp, nm, sizeof(nm))) break;
        if (!wdf_name_known(nm)) break;
        count++;
    }
    if (!count) count = wdf_rd32(tbl + (uint64_t)count * WDF_ENTRY_SIZE);
    if (!count || count > WDF_MAX_SVC) return 0;

    memset(g_svcs, 0, sizeof(g_svcs));
    for (uint32_t i = 0; i < count; i++) {
        uint8_t *e = tbl + (uint64_t)i * WDF_ENTRY_SIZE;
        wdf_svc_t *s = &g_svcs[i];
        s->entry = e;
        uint64_t sp = wdf_rd64(e + OFF_SHORT_NAME);
        if (!wdf_cstr((const char *)sp, s->name, sizeof(s->name))) s->name[0] = 0;
        s->type = wdf_rd32(e + OFF_TYPE);
        s->seen_success_count = wdf_rd64(e + OFF_SUCCESS_COUNT);
        s->seen_last_success = wdf_rd64(e + OFF_LAST_SUCCESS);
    }
    g_table = tbl;
    g_count = count;
    g_located = 1;
    wdf_log("table found by signature @%p count=%u refs=%u (fixed vaddr 0x%llx+slide)",
            tbl, count, wdf_code_refs((uint64_t)tbl), WDF_TABLE_VADDR);
    return 1;
}

// ─────────────────────────── половина 2: принимать «поздние» ответы ───────────────────────────
// В 20H392 ответ демона отбрасывается, если receive-порт принятого сообщения не равен
// [+0xa0] записи (b.ne @0x1000099c4 -> «doesn't match receive port, skipping message»).
// Время успеха при этом не обновляется, и запись «залипает». nop вместо b.ne отправляет
// такой ответ по штатной ветке: она пишет [+0xa8]=1, [+0xa9]=is_alive, строку и контекст,
// после чего штатный учёт раунда (0x100008358 -> 0x100008360..0x100008384) сам пишет
// [+0x78]=now, [+0x70]++ и обнуляет [+0x9c]. Селектор паники (2) не затрагивается.
// Запись одной инструкции в __text чужого образа: vm_protect + memcpy + сброс icache.
static int wdf_write_insn(uint8_t *insn, uint32_t value)
{
    vm_address_t page = (vm_address_t)insn & ~(vm_address_t)(vm_page_size - 1);
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t kr = vm_region_64(mach_task_self(), &page, &size, VM_REGION_BASIC_INFO_64,
                                    (vm_region_info_t)&info, &info_cnt, &object);
    if (kr == KERN_SUCCESS) {
        kr = vm_protect(mach_task_self(), page, vm_page_size, FALSE,
                        info.protection | VM_PROT_WRITE | VM_PROT_COPY);
    }
    if (kr != KERN_SUCCESS) {
        wdf_log("can't make 0x%llx writable: %s", (uint64_t)insn, mach_error_string(kr));
        return 0;
    }
    memcpy(insn, &value, sizeof(value));
    sys_icache_invalidate(insn, sizeof(value));
    return 1;
}

// Ручной тормоз: /var/log/.disable_watchdogfix (конвенция watchdoghook)
static int wdf_disabled(void)
{
    return access(WDF_DISABLE_PATH, F_OK) == 0;
}

static void wdf_revert_late_reply_patch(void)
{
    uint8_t *insn = (uint8_t *)(g_slide + (intptr_t)WDF_MISMATCH_INSN_VA);
    if (!wdf_mapped(insn, 4) || wdf_rd32(insn) != WDF_NOP) return;
    uint32_t restore = WDF_MISMATCH_INSN;
    if (wdf_write_insn(insn, restore)) {
        g_patched = 0;
        wdf_log("manual brake: b.ne@0x%llx restored", WDF_MISMATCH_INSN_VA);
    }
}

static void wdf_install_late_reply_patch(void)
{
    if (g_patched) return;
    if (!g_mh) wdf_image_init();
    if (!g_mh) return;

    uint8_t *insn = (uint8_t *)(g_slide + (intptr_t)WDF_MISMATCH_INSN_VA);
    if (!wdf_mapped(insn, 4)) {
        wdf_log("skip late-reply patch: 0x%llx not mapped", WDF_MISMATCH_INSN_VA);
        return;
    }
    uint32_t cur = wdf_rd32(insn);
    if (cur == WDF_NOP) {
        g_patched = 1;
        wdf_log("late-reply patch already applied");
        return;
    }
    if (cur != WDF_MISMATCH_INSN) {
        // Санити-чек: на 20H392 здесь b.ne. Иначе — другой билд, не патчим вслепую.
        wdf_log("late-reply patch NOT applied: insn @0x%llx = 0x%08x, expected 0x%08x",
                WDF_MISMATCH_INSN_VA, cur, WDF_MISMATCH_INSN);
        return;
    }

    // На arm64 запись в исполняемую страницу снимает CS_VALID у процесса — системные
    // хуки csops/csops_audittoken в systemhook это компенсируют (тот же приём, что у
    // ellekit-хуков watchdoghook.dylib, которые уже правят код в этом процессе).
    uint32_t nop = WDF_NOP;
    if (wdf_write_insn(insn, nop)) {
        g_patched = 1;
        wdf_log("late-reply patch applied: b.ne@0x%llx -> nop (reply port mismatch no longer drops replies)",
                WDF_MISMATCH_INSN_VA);
    }
}

// ─────────────────────────── половина 1: тик лечения ───────────────────────────
static int wdf_reply_port_shared(uint32_t idx, uint32_t reply_port)
{
    if (!reply_port) return 0;
    for (uint32_t j = 0; j < g_count; j++) {
        if (j == idx) continue;
        if (wdf_rd32(g_svcs[j].entry + OFF_REPLY_PORT) == reply_port) return 1;
    }
    return 0;
}

static void wdf_tick(void)
{
    if (wdf_disabled()) {                 // ручной тормоз: /var/log/.disable_watchdogfix
        wdf_revert_late_reply_patch();    // снимаем не только лечение, но и правку кода
        return;
    }
    if (!g_patched) wdf_install_late_reply_patch();   // тормоз сняли — вернуть патч
    if (!g_located && !wdf_locate_table()) return;

    uint64_t now = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);

    for (uint32_t i = 0; i < g_count; i++) {
        wdf_svc_t *s = &g_svcs[i];
        uint8_t *e = s->entry;
        if (!wdf_mapped(e, WDF_ENTRY_SIZE)) continue;

        uint32_t port       = wdf_rd32(e + OFF_PORT);
        uint32_t strikes    = wdf_rd32(e + OFF_STRIKES);
        uint32_t reply_port = wdf_rd32(e + OFF_REPLY_PORT);
        uint8_t  skip_crash = wdf_rd8(e + OFF_SKIP_CRASH);
        uint64_t succ_cnt   = wdf_rd64(e + OFF_SUCCESS_COUNT);
        uint64_t last_ok    = wdf_rd64(e + OFF_LAST_SUCCESS);

        // Наблюдённый успех снимает счётчик «расшевеливаний» и тормоз
        if (succ_cnt != s->seen_success_count || last_ok != s->seen_last_success) {
            s->seen_success_count = succ_cnt;
            s->seen_last_success = last_ok;
            s->heals = 0;
            s->heal_until = 0;
            s->shared_reply_logged = 0;
            continue;                              // успех виден — вмешиваться нечего
        }

        if (skip_crash) continue;                  // logd и прочие с [+0x2d]=1 — не трогаем никогда
        if (now < s->heal_until) continue;         // отступ: даём панике дойти до watchdoghook

        int foreign = wdf_reply_port_shared(i, reply_port);
        if (foreign && !s->shared_reply_logged) {
            s->shared_reply_logged = 1;
            wdf_log("%s: reply port 0x%x of the current round is shared with another record (stale round port)",
                    s->name, reply_port);
        }

        if (port == MACH_PORT_NULL) {
            // Порт уже обнулён: его переоткрывает late-discovery (0x1000094e0..0x100009524)
            // на следующем раунде. Если bootstrap_look_up не удался — порт останется 0,
            // счётчик неуспехов доберёт порог, и паника уйдёт в watchdoghook: это правильное
            // поведение для действительно мёртвого демона, вмешиваться нечем.
            continue;
        }
        if (strikes == 0 && !foreign) continue;    // запись здорова

        if (s->heals >= WDF_MAX_HEALS_PER_EPOCH) {
            s->heal_until = now + WDF_BACKOFF_NS;
            s->heals = 0;
            wdf_log("%s: still no success after %d unsticks — backoff %llus, letting watchdogd/watchedoghook escalate",
                    s->name, WDF_MAX_HEALS_PER_EPOCH, WDF_BACKOFF_NS / NSEC_PER_SEC);
            continue;
        }

        wdf_wr32(e + OFF_PORT, MACH_PORT_NULL);    // ключевая правка: снять залипший порт
        wdf_wr32(e + OFF_STRIKES, 0);              // свежее окно: порог 2 раунда не добирается
        s->heals++;
        wdf_log("%s: unstuck (strikes=%u -> 0, port=0x%x -> NULL%s), heals=%u",
                s->name, strikes, port, foreign ? ", reply port was foreign" : "", s->heals);
    }
}

// ─────────────────────────── API для watchdoghook (§7.2) ───────────────────────────
// Прицельная реанимация учёта: обнулить порт сервиса и счётчик неуспехов, чтобы
// late-discovery переоткрыл порт, а у раунда было свежее окно в 2 раунда.
// Возвращает 1 — реанимация начата, 0 — сервис не найден / таблица не найдена.
int obl1_wd_fix_revive(const char *name)
{
    if (!name) return 0;
    if (!g_located && !wdf_locate_table()) return 0;
    for (uint32_t i = 0; i < g_count; i++) {
        wdf_svc_t *s = &g_svcs[i];
        if (strcmp(s->name, name)) continue;
        s->heals = 0;
        s->heal_until = 0;
        s->shared_reply_logged = 0;
        s->revive_armed = 1;
        s->revive_base_count = wdf_rd64(s->entry + OFF_SUCCESS_COUNT);
        s->revive_base_ts = wdf_rd64(s->entry + OFF_LAST_SUCCESS);
        wdf_wr32(s->entry + OFF_PORT, MACH_PORT_NULL);
        wdf_wr32(s->entry + OFF_STRIKES, 0);
        wdf_log("revive: %s port cleared, strikes cleared (baseline success_count=%llu)", name,
                s->revive_base_count);
        return 1;
    }
    wdf_log("revive: service '%s' not found in watchdogd table", name);
    return 0;
}

// 1 — с момента revive у сервиса появился успешный чек-ин (учёт ожил).
int obl1_wd_fix_revived(const char *name)
{
    if (!name || !g_located) return 0;
    for (uint32_t i = 0; i < g_count; i++) {
        wdf_svc_t *s = &g_svcs[i];
        if (strcmp(s->name, name)) continue;
        if (!s->revive_armed) return 0;
        uint64_t cnt = wdf_rd64(s->entry + OFF_SUCCESS_COUNT);
        uint64_t ts = wdf_rd64(s->entry + OFF_LAST_SUCCESS);
        if (cnt > s->revive_base_count || ts > s->revive_base_ts) {
            s->revive_armed = 0;
            wdf_log("revive: %s is checking in again (success_count %llu -> %llu)", name,
                    s->revive_base_count, cnt);
            return 1;
        }
        return 0;
    }
    return 0;
}

// Диагностика для INSTALL.md/проверки: 1 — таблица найдена, 2 — плюс снят отброс ответов.
int obl1_wd_fix_status(void)
{
    int st = 0;
    if (g_located || wdf_locate_table()) st |= 1;
    if (g_patched) st |= 2;
    return st;
}

// ─────────────────────────── запуск ───────────────────────────
__attribute__((constructor)) static void wdf_initializer(void)
{
    wdf_image_init();
    wdf_locate_table();
    if (wdf_disabled()) {
        wdf_log("manual brake present (%s): late-reply patch not applied, healer idle", WDF_DISABLE_PATH);
    } else {
        wdf_install_late_reply_patch();
    }

    wdf_log("loaded: status=%d (1=table, 2=late-reply patch), table=%p count=%u slide=0x%lx",
            obl1_wd_fix_status(), g_table, g_count, (long)g_slide);

    dispatch_queue_t q = dispatch_queue_create("obl1.watchdogfix", DISPATCH_QUEUE_SERIAL);
    g_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
    dispatch_source_set_timer(g_timer, dispatch_time(DISPATCH_TIME_NOW, WDF_TICK_NS),
                              WDF_TICK_NS, 200ull * NSEC_PER_MSEC);
    dispatch_source_set_event_handler(g_timer, ^{
        wdf_tick();
    });
    dispatch_resume(g_timer);
}
