#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <xpc/xpc.h>
#include <IOKit/IOKitLib.h>
#include <libjailbreak/jbclient_xpc.h>

#include <substrate.h>

#include <dispatch/dispatch.h>
#include <os/log.h>
#include <os/lock.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>

int reboot3(uint64_t flags, ...);
#define RB2_USERREBOOT (0x2000000000000000llu)

// ───────────────────────── 20H392 ─────────────────────────
// Раунд чек-инов watchdogd = 10 c (dispatch_time(NOW, 0x2540BE400) @0x10000810c).
#define WDH_ROUND_NS		(10ull * NSEC_PER_SEC)
// Порог «нет успешных чек-инов»: [+0x9c] >= 2 раунда (порог @0x10001b8ac).
#define WDH_PANIC_ROUNDS	2
// Короткие имена сервисов из таблицы watchdogd 20H392 (поле +0x18, порядок записей).
static const char *kWdhKnownServices[] = {
	"backboardd", "PreboardService", "SpringBoard", "CarPlay", "hidd.nonui",
	"mediaserverd", "darwinaudiod", "remoted", "logd", "thermalmonitord",
	"runningboardd", "wifid", "configd", "automationdevicemonitoringd",
};
static const size_t kWdhKnownCount = sizeof(kWdhKnownServices) / sizeof(kWdhKnownServices[0]);

static void wdhLog(const char *fmt, ...)
{
	char buf[512];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_DEFAULT, "watchdoghook: %{public}s", buf);
}

// Сервис из панического сообщения «no successful checkins from %s in %llu seconds»:
// ищем известное короткое имя из таблицы watchdogd (20H392).
static const char *wdhKnownServiceInMessage(const char *msg)
{
	if (!msg) return NULL;
	for (size_t i = 0; i < kWdhKnownCount; i++) {
		const char *name = kWdhKnownServices[i];
		const char *hit = strstr(msg, name);
		if (!hit) continue;
		char after = hit[strlen(name)];
		if (after == '\0' || after == ' ' || after == '\n' || after == '\t') return name;
	}
	return NULL;
}

// ───────── Прицельная реанимация учёта вместо немедленного userspace-reboot ─────────
// API watchdogfix.dylib (грузится рядом тем же systemhook): сброс залипшего
// mach-порта сервиса [svc+0x58] и счётчика неуспехов, затем проверка, ожил ли учёт.
static int (*wdFixRevive)(const char *name) = NULL;
static int (*wdFixRevived)(const char *name) = NULL;

// Путь к watchdogfix.dylib без jbroot-API: свой образ лежит рядом ($BR/basebin/watchdoghook.dylib).
static void *wdhOpenFix(void)
{
	char self[PATH_MAX];
	Dl_info info;
	if (dladdr((const void *)&wdhOpenFix, &info) && info.dli_fname) {
		strlcpy(self, info.dli_fname, sizeof(self));
		char *slash = strrchr(self, '/');
		if (slash) {
			strlcpy(slash + 1, "watchdogfix.dylib", sizeof(self) - (size_t)(slash + 1 - self));
			void *handle = dlopen(self, RTLD_NOW);
			if (handle) return handle;
		}
	}
	// Запасной путь: образ уже загружен systemhook — берём готовое имя из списка dyld
	for (uint32_t i = 0; i < _dyld_image_count(); i++) {
		const char *nm = _dyld_get_image_name(i);
		if (nm && strstr(nm, "watchdogfix.dylib")) {
			void *handle = dlopen(nm, RTLD_NOW);
			if (handle) return handle;
		}
	}
	return NULL;
}

static void wdhLoadFixApi(void)
{
	static dispatch_once_t once;
	dispatch_once(&once, ^{
		void *handle = wdhOpenFix();
		if (!handle) {
			wdhLog("watchdogfix.dylib not loaded: %s — панический путь работает как раньше", dlerror());
			return;
		}
		wdFixRevive = (int (*)(const char *))dlsym(handle, "obl1_wd_fix_revive");
		wdFixRevived = (int (*)(const char *))dlsym(handle, "obl1_wd_fix_revived");
		wdhLog("watchdogfix API: revive=%p revived=%p", (void *)wdFixRevive, (void *)wdFixRevived);
	});
}

static os_unfair_lock gPendingLock = OS_UNFAIR_LOCK_INIT;
static struct {
	int active;
	char name[64];
	uint64_t armedAt;
	int extraRounds;
	char *panicMessage;
} gPending;

static void wdhPendingClear(void)
{
	if (gPending.panicMessage) {
		free(gPending.panicMessage);
		gPending.panicMessage = NULL;
	}
	gPending.active = 0;
	gPending.name[0] = 0;
	gPending.armedAt = 0;
	gPending.extraRounds = 0;
}

// Штатный путь: перехват паники + userspace-reboot. Вызывается, когда прицельная
// реанимация не помогла (или недоступна) — семантика selector 2 не меняется.
static void wdhFallbackPanicPath(const char *msg)
{
	int r = jbclient_watchdog_intercept_userspace_panic(msg);
	if (r == 0) {
		reboot3(RB2_USERREBOOT);
	}
}

// Через WDH_PANIC_ROUNDS раундов после реанимации: если учёт не ожил — штатный путь.
static void wdhArmRebootCheck(const char *service)
{
	char *serviceCopy = strdup(service);   // блок захватывает указатель, а не массив
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(WDH_ROUND_NS * WDH_PANIC_ROUNDS)),
	               dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
		char *msg = NULL;
		os_unfair_lock_lock(&gPendingLock);
		if (serviceCopy && gPending.active && !strcmp(gPending.name, serviceCopy)) {
			if (wdFixRevived && wdFixRevived(serviceCopy)) {
				wdhLog("%s: checkins restored, panic request dropped (no reboot)", serviceCopy);
				wdhPendingClear();
			} else {
				msg = gPending.panicMessage;    // забираем текст, ребут — вне лока
				gPending.panicMessage = NULL;
				wdhLog("%s: no checkins %d rounds after revive — userspace reboot path", serviceCopy,
				       WDH_PANIC_ROUNDS);
				wdhPendingClear();
			}
		}
		os_unfair_lock_unlock(&gPendingLock);
		if (msg) {
			wdhFallbackPanicPath(msg);
			free(msg);
		}
		free(serviceCopy);
	});
}

// Возврат 1 — панический запрос удержан (реанимация запущена/идёт),
// 0 — идти штатным путём (перехват паники + reboot3).
static int wdhTryReviveInsteadOfReboot(const char *msg, const char *service)
{
	wdhLoadFixApi();
	if (!wdFixRevive || !wdFixRevived) return 0;

	os_unfair_lock_lock(&gPendingLock);
	if (gPending.active && !strcmp(gPending.name, service)) {
		if (wdFixRevived(service)) {
			wdhLog("%s: checkins restored, panic request dropped (no reboot)", service);
			wdhPendingClear();
			os_unfair_lock_unlock(&gPendingLock);
			return 1;
		}
		if (gPending.extraRounds < WDH_PANIC_ROUNDS) {
			gPending.extraRounds++;
			wdhLog("%s: waiting extra round %d/%d after revive", service, gPending.extraRounds,
			       WDH_PANIC_ROUNDS);
			os_unfair_lock_unlock(&gPendingLock);
			return 1;
		}
		wdhLog("%s: not revived after %d rounds — falling through to userspace reboot", service,
		       WDH_PANIC_ROUNDS);
		wdhPendingClear();
		os_unfair_lock_unlock(&gPendingLock);
		return 0;
	}
	os_unfair_lock_unlock(&gPendingLock);

	// Первый панический запрос по этому сервису: реанимация учёта + лишний раунд ожидания.
	if (!wdFixRevive(service)) return 0;

	os_unfair_lock_lock(&gPendingLock);
	wdhPendingClear();
	gPending.active = 1;
	strlcpy(gPending.name, service, sizeof(gPending.name));
	gPending.armedAt = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
	gPending.extraRounds = 1;
	gPending.panicMessage = strdup(msg ? msg : "");
	os_unfair_lock_unlock(&gPendingLock);

	wdhLog("%s: revive requested (port reset + fresh strike window), holding panic", service);
	wdhArmRebootCheck(service);
	return 1;
}

kern_return_t (*IOConnectCallStructMethod_orig)(mach_port_t connection, uint32_t selector, const void *inputStruct, size_t inputStructCnt, void *outputStruct, size_t *outputStructCnt) = NULL;
kern_return_t (*IOServiceOpen_orig)(io_service_t service, task_port_t owningTask, uint32_t type, io_connect_t *connect);
mach_port_t gIOWatchdogConnection = MACH_PORT_NULL;

kern_return_t IOServiceOpen_hook(io_service_t service, task_port_t owningTask, uint32_t type, io_connect_t *connect)
{
	kern_return_t orig = IOServiceOpen_orig(service, owningTask, type, connect);
	if (orig == KERN_SUCCESS && connect) {
		if (IOObjectConformsTo(service, "IOWatchdog")) {
			// save mach port of IOWatchdog for check later
			gIOWatchdogConnection = *connect;
		}
	}
	return orig;
}

kern_return_t IOConnectCallStructMethod_hook(mach_port_t connection, uint32_t selector, const void *inputStruct, size_t inputStructCnt, void *outputStruct, size_t *outputStructCnt)
{
	if (connection == gIOWatchdogConnection) {
		if (selector == 2) {
			// Перехват паник сохранён. Отличие: для известного сервиса сначала
			// пробуем прицельную реанимацию учёта, и только если она не помогла
			// (или сервис неизвестен) — штатный userspace-reboot.
			const char *message = (const char *)inputStruct;
			if (message && strstr(message, "no successful checkins from")) {
				const char *service = wdhKnownServiceInMessage(message);
				if (service && wdhTryReviveInsteadOfReboot(message, service)) {
					return 0;   // паника предотвращена, глобального ребута нет
				}
			}
			int r = jbclient_watchdog_intercept_userspace_panic(message);
			if (r == 0) {
				reboot3(RB2_USERREBOOT);
				// Вернулся — значит ребут НЕ состоялся: отдаём панику штатному пути,
				// чтобы устройство ушло в обычный panic-ребут с логом, а не в тихий висяк.
				wdhLog("reboot3 returned: passing panic through to watchdogd");
			} else {
				// W2/H2/V14: jbserver недоступен. НИКОГДА не возвращать ненулевой код —
				// по дизасму 0x100005704 это __os_crash внутри watchdogd -> паника SoC.
				wdhLog("intercept failed (%d): passing panic through to watchdogd", r);
			}
			if (!IOConnectCallStructMethod_orig) {
				// Оригинал не захукался (W5): держим панику вместо краха watchdogd
				wdhLog("original IOConnectCallStructMethod is NULL, holding panic");
				return 0;
			}
			return IOConnectCallStructMethod_orig(connection, selector, inputStruct, inputStructCnt, outputStruct, outputStructCnt);
		}
	}
	return IOConnectCallStructMethod_orig(connection, selector, inputStruct, inputStructCnt, outputStruct, outputStructCnt);
}

__attribute__((constructor)) static void initializer(void)
{
/////////////////////////////
if(access("/var/log/.disable_watchdoghook", F_OK) == 0) {
	return;
}
///////////////////////////////

	MSHookFunction(IOServiceOpen, (void *)&IOServiceOpen_hook, (void **)&IOServiceOpen_orig);
	MSHookFunction(IOConnectCallStructMethod, (void *)&IOConnectCallStructMethod_hook, (void **)&IOConnectCallStructMethod_orig);

	// watchdogfix.dylib грузится следом из systemhook; его API берём лениво при первой панике
	wdhLog("loaded (revive-instead-of-reboot guard armed)");
}
