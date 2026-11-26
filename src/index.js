const AUTO_REFRESH_MS = 15000;

const state = {
    firewallBackend: "ufw",
    firewallBackends: [],
    firewallBackendsReady: false,
    firewallChains: [],
    firewallPersist: null,
    firewallNotices: [],
    firewallReadOnly: false,
    firewallManager: "",
    securityLogSource: "all",
    firewallRules: {
        columns: [],
        rows: [],
        emptyText: "Keine Regeldaten vorhanden.",
        page: 1,
        pageSize: 10,
    },
    firewallDialog: {
        open: false,
        mode: "",
        busy: false,
        error: "",
    },
    currentJail: "",
    fail2banService: "fail2ban.service",
    autoRefreshTimer: null,
    refreshLocks: {
        firewall: null,
        fail2ban: null,
        logs: null,
    },
    securityLogsRefreshPending: false,
    toolInstalled: {
        ufw: null,
        iptables: null,
        nftables: null,
        firewalld: null,
        fail2ban: null,
    },
    toolCommand: {
        ufw: "ufw",
        iptables: "iptables",
        nftables: "nft",
        firewalld: "firewall-cmd",
        fail2ban: "fail2ban-client",
    },
    installDialog: {
        open: false,
        toolId: "",
        packageNames: [],
        data: null,
        checking: false,
        busy: false,
        progressMessage: "",
        error: "",
        cancel: null,
    },
    confirmDialog: {
        open: false,
        title: "",
        message: "",
        confirmLabel: "Bestätigen",
        variant: "danger",
        resolve: null,
    },
    superuserAllowed: null,
    superuserError: "",
    superuserProxy: null,
    superuserPermission: null,
    superuserDialog: {
        open: false,
        methods: [],
        selectedMethod: "",
        message: "",
        prompt: "",
        value: "",
        echo: false,
        error: "",
        errorTone: "warning",
        inProgress: false,
        promptSeen: false,
        cleanup: null,
        closeAfterSuccess: false,
    },
};

const SECURITY_LOG_FETCH_LIMIT = 200;
const SECURITY_LOG_DISPLAY_LIMIT = 10;

const SECURITY_LOG_SOURCES = [
    {
        id: "all",
        label: "Alle Dienste",
        units: ["ufw.service", "iptables.service", "ip6tables.service", "netfilter-persistent.service", "nftables.service", "firewalld.service", "fail2ban.service"],
        kernelScope: "firewall",
    },
    {
        id: "ufw",
        label: "UFW",
        units: ["ufw.service"],
        kernelScope: "ufw",
    },
    {
        id: "iptables",
        label: "iptables / nftables",
        units: ["iptables.service", "ip6tables.service", "netfilter-persistent.service", "nftables.service"],
        kernelScope: "iptables",
    },
    {
        id: "firewalld",
        label: "firewalld",
        units: ["firewalld.service"],
    },
    {
        id: "fail2ban",
        label: "Fail2Ban",
        units: ["fail2ban.service"],
    },
];

const REQUIRED_TOOLS = {
    ufw: {
        id: "ufw",
        label: "UFW",
        command: "ufw",
        commands: ["ufw"],
        paths: ["/usr/sbin/ufw", "/sbin/ufw"],
        packages: ["ufw"],
        installTitle: "UFW installieren",
        installCopy: "Installiere UFW, um UFW-Regeln zu verwalten.",
    },
    iptables: {
        id: "iptables",
        label: "iptables",
        command: "iptables",
        commands: ["iptables", "iptables-nft", "iptables-legacy"],
        paths: ["/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables", "/usr/sbin/iptables-nft", "/usr/sbin/iptables-legacy"],
        packages: ["iptables"],
        packageCandidates: [["iptables"], ["iptables-nft"], ["iptables-services"]],
        installTitle: "iptables installieren",
        installCopy: "Installiere iptables, um Regeln der INPUT-Kette zu verwalten.",
    },
    nftables: {
        id: "nftables",
        label: "nftables",
        command: "nft",
        commands: ["nft"],
        paths: ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"],
        packages: ["nftables"],
        packageCandidates: [["nftables"]],
        installTitle: "nftables installieren",
        installCopy: "Installiere nftables, um dessen Regeln anzuzeigen und zu verwalten.",
    },
    firewalld: {
        id: "firewalld",
        label: "firewalld",
        command: "firewall-cmd",
        commands: ["firewall-cmd"],
        paths: ["/usr/bin/firewall-cmd", "/usr/sbin/firewall-cmd", "/bin/firewall-cmd", "/sbin/firewall-cmd"],
        packages: ["firewalld"],
        packageCandidates: [["firewalld"]],
        installTitle: "firewalld installieren",
        installCopy: "Installiere firewalld, um Firewall-Zonen anzuzeigen und zu verwalten.",
    },
    fail2ban: {
        id: "fail2ban",
        label: "Fail2Ban",
        command: "fail2ban-client",
        commands: ["fail2ban-client"],
        paths: ["/usr/bin/fail2ban-client", "/usr/sbin/fail2ban-client"],
        packages: ["fail2ban"],
        packageCandidates: [["fail2ban"], ["fail2ban-server"]],
        installTitle: "Fail2Ban installieren",
        installCopy: "Installiere Fail2Ban, um Jails anzuzeigen und gesperrte IP-Adressen zu verwalten. ",
    },
};

const INSTALL_PROGRESS_TYPE = {
    DOWNLOADING: 0,
    UPDATING: 1,
    INSTALLING: 2,
    REMOVING: 3,
    REINSTALLING: 4,
    DOWNGRADING: 5,
};

const PACKAGEKIT_ENUM = {
    EXIT_SUCCESS: 1,
    EXIT_CANCELLED: 3,
    INFO_DOWNLOADING: 10,
    INFO_UPDATING: 11,
    INFO_INSTALLING: 12,
    INFO_REMOVING: 13,
    INFO_REINSTALLING: 19,
    INFO_DOWNGRADING: 20,
    STATUS_WAIT: 1,
    STATUS_WAITING_FOR_LOCK: 30,
    FILTER_NEWEST: (1 << 16),
    FILTER_ARCH: (1 << 18),
    FILTER_NOT_SOURCE: (1 << 21),
    TRANSACTION_FLAG_SIMULATE: (1 << 2),
};

const PACKAGEKIT_INSTALL_PROGRESS_MAP = {
    [PACKAGEKIT_ENUM.INFO_DOWNLOADING]: INSTALL_PROGRESS_TYPE.DOWNLOADING,
    [PACKAGEKIT_ENUM.INFO_UPDATING]: INSTALL_PROGRESS_TYPE.UPDATING,
    [PACKAGEKIT_ENUM.INFO_INSTALLING]: INSTALL_PROGRESS_TYPE.INSTALLING,
    [PACKAGEKIT_ENUM.INFO_REMOVING]: INSTALL_PROGRESS_TYPE.REMOVING,
    [PACKAGEKIT_ENUM.INFO_REINSTALLING]: INSTALL_PROGRESS_TYPE.REINSTALLING,
    [PACKAGEKIT_ENUM.INFO_DOWNGRADING]: INSTALL_PROGRESS_TYPE.DOWNGRADING,
};

const PACKAGEKIT_TRANSACTION_INTERFACE = "org.freedesktop.PackageKit.Transaction";
const SYSTEM_COMMAND_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const FAIL2BAN_SERVICE_CANDIDATES = ["fail2ban.service", "fail2ban-server.service"];
let packageManager = null;
let packageKitClient = null;
let dnf5Client = null;

function getElement(id) {
    return document.getElementById(id);
}

function setHidden(id, hidden) {
    const element = getElement(id);
    if (element)
        element.hidden = hidden;
}

function withRefreshLock(key, callback) {
    if (state.refreshLocks[key])
        return state.refreshLocks[key];

    const task = Promise.resolve()
        .then(callback)
        .finally(() => {
            state.refreshLocks[key] = null;
        });

    state.refreshLocks[key] = task;
    return task;
}

function stopAutoRefresh() {
    if (state.autoRefreshTimer) {
        window.clearInterval(state.autoRefreshTimer);
        state.autoRefreshTimer = null;
    }
}

function refreshSecurityPage() {
    if (state.superuserAllowed === null)
        return Promise.resolve();

    return Promise.all([
        refreshFirewallStatus(),
        refreshFail2BanStatus(),
        refreshSecurityLogs(),
    ]);
}

function startAutoRefresh() {
    stopAutoRefresh();

    if (state.superuserAllowed === null || document.hidden)
        return;

    state.autoRefreshTimer = window.setInterval(() => {
        if (document.hidden || state.superuserAllowed === null)
            return;
        refreshSecurityPage();
    }, AUTO_REFRESH_MS);
}

function applyDarkMode(styleOverride) {
    const style = styleOverride || window.localStorage.getItem("shell:style") || "auto";
    const prefersDark = window.matchMedia?.("(prefers-color-scheme: dark)").matches;
    const darkMode = style === "dark" || (style === "auto" && prefersDark);
    document.documentElement.classList.toggle("pf-v6-theme-dark", darkMode);
}

function bindDarkMode() {
    applyDarkMode();

    window.addEventListener("storage", event => {
        if (event.key === "shell:style")
            applyDarkMode();
    });

    window.addEventListener("cockpit-style", event => {
        if (event instanceof CustomEvent)
            applyDarkMode(event.detail?.style);
    });

    const media = window.matchMedia?.("(prefers-color-scheme: dark)");
    media?.addEventListener?.("change", () => applyDarkMode());
}

function computeSuperuserAllowed() {
    if (!state.superuserProxy?.valid || state.superuserProxy.Current === "init")
        return null;

    return state.superuserProxy.Current !== "none";
}

function renderSuperuserDialog() {
    const dialog = getElement("security-auth-dialog");
    const alert = getElement("security-auth-alert");
    const title = getElement("security-auth-title");
    const message = getElement("security-auth-message");
    const methodField = getElement("security-auth-method-field");
    const methodSelect = getElement("security-auth-method");
    const promptField = getElement("security-auth-prompt-field");
    const promptLabel = getElement("security-auth-prompt-label");
    const promptInput = getElement("security-auth-input");
    const submit = getElement("security-auth-submit");
    const cancel = getElement("security-auth-cancel");

    if (!dialog || !alert || !title || !message || !methodField || !methodSelect || !promptField || !promptLabel || !promptInput || !submit || !cancel)
        return;

    const current = state.superuserDialog;
    dialog.hidden = !current.open;

    if (!current.open)
        return;

    title.textContent = "Zum Administratorzugriff wechseln";

    setAlert("security-auth-alert", current.error
        ? { title: current.error, variant: current.errorTone === "danger" ? "danger" : "warning" }
        : {});

    methodField.hidden = current.methods.length <= 1 || Boolean(current.prompt);
    methodSelect.replaceChildren();
    current.methods.forEach(method => {
        const option = document.createElement("option");
        option.value = method.id;
        option.textContent = method.label;
        option.selected = method.id === current.selectedMethod;
        methodSelect.append(option);
    });
    methodSelect.disabled = current.inProgress;

    message.hidden = !current.message;
    message.textContent = current.message;

    promptField.hidden = !current.prompt;
    promptLabel.textContent = current.prompt || "Passwort";
    promptInput.type = current.echo ? "text" : "password";
    promptInput.value = current.value;
    promptInput.disabled = current.inProgress;

    submit.disabled = current.inProgress;
    cancel.disabled = current.inProgress;

    if (current.prompt)
        submit.textContent = current.inProgress ? "Authentifizierung läuft..." : "Authentifizieren";
    else
        submit.textContent = current.inProgress ? "Authentifizierung läuft..." : "Authentifizieren";

    window.setTimeout(() => {
        if (!state.superuserDialog.open)
            return;
        if (!promptField.hidden)
            promptInput.focus();
        else if (!methodField.hidden)
            methodSelect.focus();
        else
            submit.focus();
    }, 0);
}

function closeSuperuserDialog(options = {}) {
    if (options.stop !== false && state.superuserProxy?.valid)
        state.superuserProxy.Stop().catch(() => {});

    resetSuperuserDialog();
    renderSuperuserDialog();
}

function getPreferredSuperuserMethod(methods) {
    if (!methods.length)
        return "sudo";

    const sudo = methods.find(method => method.id === "sudo");
    return (sudo || methods[0]).id;
}

function updateSuperuserDialog(patch) {
    state.superuserDialog = {
        ...state.superuserDialog,
        ...patch,
    };
    renderSuperuserDialog();
}

async function invokeSuperuserStart(method) {
    try {
        return await state.superuserProxy.Start(method);
    } catch (error) {
        const message = formatError(error);
        if (/argument|signature|type/i.test(message))
            return state.superuserProxy.Start();
        throw error;
    }
}

async function startSuperuserAuthentication(method) {
    if (!state.superuserProxy?.valid || typeof state.superuserProxy.Start !== "function")
        throw new Error("In dieser Umgebung kann der Administratorzugriff nicht direkt über diese Seite aktiviert werden.");

    const promptListener = (_event, message, prompt, value, _unused, echo, hintError) => {
        updateSuperuserDialog({
            message: normalizePromptText(message, "Bitte authentifizieren, um Administratorrechte zu erhalten"),
            prompt: normalizePromptText(prompt, "Passwort"),
            value: String(unwrapVariant(value) || ""),
            echo: Boolean(unwrapVariant(echo)),
            inProgress: false,
            error: hintError ? normalizePromptText(hintError) : "",
            errorTone: state.superuserDialog.promptSeen ? "danger" : "warning",
            promptSeen: true,
        });
    };

    updateSuperuserDialog({
        open: true,
        message: "Bitte authentifizieren, um Administratorrechte zu erhalten",
        prompt: "",
        value: "",
        echo: false,
        error: "",
        errorTone: "warning",
        inProgress: true,
        promptSeen: false,
    });

    state.superuserProxy.addEventListener("Prompt", promptListener);
    updateSuperuserDialog({
        cleanup: () => state.superuserProxy?.removeEventListener("Prompt", promptListener),
    });

    try {
        await invokeSuperuserStart(method);
        closeSuperuserDialog({ stop: false });
    } catch (error) {
        const message = formatError(error);
        if (message !== "cancelled") {
            updateSuperuserDialog({
                inProgress: false,
                prompt: "",
                message: "",
                error: normalizePromptText(message, "Fehler beim Wechsel zum Administratorzugriff"),
                errorTone: "danger",
            });
        } else {
            closeSuperuserDialog();
        }
    }
}

async function handleSuperuserDialogSubmit(event) {
    event.preventDefault();
    const current = state.superuserDialog;
    if (!current.open || current.inProgress)
        return;

    if (current.prompt) {
        updateSuperuserDialog({
            inProgress: true,
            error: "",
        });
        state.superuserProxy?.Answer(current.value);
        return;
    }

    const methodSelect = getElement("security-auth-method");
    const selectedMethod = typeof methodSelect?.value === "string" && methodSelect.value
        ? methodSelect.value
        : getPreferredSuperuserMethod(current.methods);

    updateSuperuserDialog({
        selectedMethod,
    });
    await startSuperuserAuthentication(selectedMethod);
}

function handleSuperuserDialogInput(event) {
    if (event.target?.id === "security-auth-input") {
        updateSuperuserDialog({
            value: event.target.value,
        });
        return;
    }

    if (event.target?.id === "security-auth-method") {
        updateSuperuserDialog({
            selectedMethod: event.target.value,
        });
    }
}

async function requestSuperuserAccess() {
    if (state.superuserAllowed === true || state.superuserDialog.open)
        return;

    state.superuserError = "";
    renderAccessState();

    if (!state.superuserProxy?.valid || typeof state.superuserProxy.Start !== "function") {
        state.superuserError = " In dieser Umgebung kann der Administratorzugriff nicht direkt über diese Seite aktiviert werden.";
        renderAccessState();
        return;
    }

    const methods = getSuperuserMethods();
    updateSuperuserDialog({
        open: true,
        methods,
        selectedMethod: getPreferredSuperuserMethod(methods),
        message: methods.length > 1 ? "" : "Bitte authentifizieren, um Administratorrechte zu erhalten",
        prompt: "",
        value: "",
        echo: false,
        error: "",
        errorTone: "warning",
        inProgress: false,
        promptSeen: false,
        cleanup: null,
    });

    await state.superuserProxy.Stop().catch(() => {});
    if (!state.superuserDialog.open)
        return;

    if (methods.length <= 1)
        await startSuperuserAuthentication(getPreferredSuperuserMethod(methods));
    else
        renderSuperuserDialog();
}

const ADMIN_REQUIRED_HINT = "Administratorrechte erforderlich.";

function updateWritableElements() {
    const writable = isWritable();
    document.querySelectorAll("[data-requires-admin]").forEach(element => {
        // Cockpit keeps privileged controls visible but disabled, with a tooltip
        // explaining why, instead of hiding them.
        if (element.tagName === "FORM") {
            element.querySelectorAll("button, input, select").forEach(control => {
                control.disabled = !writable;
            });
            return;
        }

        element.disabled = !writable;
        if (writable)
            element.removeAttribute("title");
        else
            element.title = ADMIN_REQUIRED_HINT;
    });
    updateFirewallActionBar();
}

function renderAccessState() {
    const pageContent = document.querySelector(".page-content");
    const panel = getElement("security-access-panel");
    const copy = getElement("security-access-copy");
    const spinner = getElement("security-access-spinner");
    const pending = state.superuserAllowed === null;
    const writable = isWritable();

    // The page itself is never gated on admin rights: unprivileged sessions get
    // the read-only view and only the mutating controls are withheld.
    if (pageContent)
        pageContent.hidden = pending;
    setHidden("security-access-panel", !pending);

    if (pending) {
        if (panel)
            panel.classList.add("is-loading");
        if (spinner)
            spinner.hidden = false;
        if (copy)
            copy.textContent = "Administratorrechte der aktuellen Sitzung werden geprüft.";
        stopAutoRefresh();
    } else {
        if (panel)
            panel.classList.remove("is-loading");
        if (spinner)
            spinner.hidden = true;
        startAutoRefresh();
    }

    const banner = getElement("security-readonly-panel");
    const bannerCopy = getElement("security-readonly-copy");
    const bannerAction = getElement("security-readonly-action");

    if (banner)
        banner.hidden = pending || writable;

    if (bannerCopy) {
        bannerCopy.textContent = state.superuserError
            ? `Diese Sitzung hat keine Administratorrechte und kann nur den Status anzeigen.${state.superuserError}`
            : "Diese Sitzung hat keine Administratorrechte und kann nur den Status anzeigen. Zum Ändern der Firewall oder von Fail2Ban oder zum Installieren von Software zuerst den Administratorzugriff aktivieren.";
    }

    if (bannerAction)
        bannerAction.hidden = Boolean(state.superuserError);

    updateWritableElements();
}

function handleSuperuserStateChange(nextAllowed) {
    const previous = state.superuserAllowed;
    state.superuserAllowed = nextAllowed;
    if (previous !== nextAllowed)
        resetDnf5Connection();
    if (nextAllowed !== false)
        state.superuserError = "";
    if (nextAllowed === true && state.superuserDialog.open)
        closeSuperuserDialog({ stop: false });
    renderAccessState();

    // Re-read on every transition: the session may have gained or lost the
    // ability to see privileged state, and the buttons follow it. Backend
    // detection triggers its own read once the preferred backend is known.
    if (previous !== nextAllowed && nextAllowed !== null && state.firewallBackendsReady)
        refreshSecurityPage();
}

function initSuperuser() {
    state.superuserProxy = cockpit.dbus(null, { bus: "internal" }).proxy("cockpit.Superuser", "/superuser");
    state.superuserProxy.addEventListener("changed", () => {
        handleSuperuserStateChange(computeSuperuserAllowed());
    });

    state.superuserProxy.wait(() => {
        if (!state.superuserProxy.valid) {
            state.superuserPermission = cockpit.permission({ admin: true });
            const updatePermission = () => {
                handleSuperuserStateChange(state.superuserPermission.allowed);
            };
            state.superuserPermission.addEventListener("changed", updatePermission);
            updatePermission();
            return;
        }

        handleSuperuserStateChange(computeSuperuserAllowed());
    });
}

function spawnCommand(args, superuser) {
    return cockpit.spawn(args, {
        superuser,
        err: "out",
        environ: [`PATH=${SYSTEM_COMMAND_PATH}`, "LC_ALL=C"],
    }).then(output => output.trim());
}

// Writes need the superuser bridge; failing loudly is the right behaviour there.
function run(args) {
    return spawnCommand(args, "require");
}

function capture(argsOrScript) {
    return run(argsOrScript)
        .then(output => ({ ok: true, output }))
        .catch(error => ({ ok: false, output: formatError(error) }));
}

// Reads use the superuser bridge when the session already holds it and fall back
// to the unprivileged session otherwise. That fallback is what lets a plain user
// see whatever the host allows without being locked out of the whole page.
function captureRead(argsOrScript) {
    return spawnCommand(argsOrScript, "try")
        .then(output => ({ ok: true, output }))
        .catch(error => ({ ok: false, output: formatError(error) }));
}

const PERMISSION_ERROR_PATTERN = /permission denied|must be root|not permitted|access denied|authentication is required|you must be root|operation not permitted/i;

function isPermissionError(text) {
    return PERMISSION_ERROR_PATTERN.test(String(text || ""));
}

function isWritable() {
    return state.superuserAllowed === true;
}

function runUnprivileged(args) {
    return cockpit.spawn(args, {
        err: "out",
        environ: [`PATH=${SYSTEM_COMMAND_PATH}`, "LC_ALL=C"],
    }).then(output => output.trim());
}

function captureUnprivileged(args) {
    return runUnprivileged(args)
        .then(output => ({ ok: true, output }))
        .catch(error => ({ ok: false, output: formatError(error) }));
}

function getToolCommand(toolId) {
    return state.toolCommand[toolId] || REQUIRED_TOOLS[toolId]?.command || toolId;
}

async function checkToolInstalled(toolId, options = {}) {
    const tool = REQUIRED_TOOLS[toolId];
    if (!tool)
        return false;

    if (options.force !== true && state.toolInstalled[toolId] !== null)
        return state.toolInstalled[toolId];

    const commands = tool.commands || [tool.command];
    const paths = tool.paths || [];
    // Decide by the path we print, not by the script's exit status. cockpit.spawn's
    // resolve/reject behaviour around non-zero exits proved unreliable here (a missing
    // tool was still being treated as installed), and a login shell (-lc) can leak
    // /etc/profile output into stdout. Use a plain `sh -c` that always exits 0 and only
    // prints a path when the tool is actually found.
    const script = [
        `PATH=${SYSTEM_COMMAND_PATH}`,
        ...commands.map(command => `command -v ${command} 2>/dev/null && exit 0`),
        ...paths.map(path => `[ -x ${path} ] && echo ${path} && exit 0`),
        "exit 0",
    ].join("\n");
    const result = await captureUnprivileged(["sh", "-c", script]);
    const found = result.ok
        ? (result.output.split(/\r?\n/).map(line => line.trim()).find(Boolean) || "")
        : "";
    state.toolInstalled[toolId] = Boolean(found);
    if (found)
        state.toolCommand[toolId] = found;
    return Boolean(found);
}

function createPackageManagerError(name, message) {
    const error = new Error(message);
    error.name = name;
    return error;
}

async function isImmutableOS() {
    try {
        const options = await runUnprivileged(["findmnt", "-T", "/usr", "-n", "-o", "VFS-OPTIONS"]);
        return options.split(",").includes("ro");
    } catch (error) {
        console.debug("Unable to detect immutable OS", error);
        return false;
    }
}

async function detectDnf5Daemon() {
    const client = cockpit.dbus("org.rpm.dnf.v0", { superuser: "try" });
    let detected = false;

    try {
        await client.call("/org/rpm/dnf/v0", "org.freedesktop.DBus.Peer", "Ping", []);
        detected = true;
    } catch (error) {
        console.debug("dnf5daemon not supported", error);
    } finally {
        client.close();
    }

    return detected;
}

async function detectPackageKit() {
    const client = cockpit.dbus("org.freedesktop.PackageKit", { superuser: "try" });
    let detected = false;

    try {
        await client.call("/org/freedesktop/PackageKit", "org.freedesktop.DBus.Properties", "Get", ["org.freedesktop.PackageKit", "VersionMajor"]);
        detected = true;
    } catch (error) {
        console.debug("PackageKit not supported", error);
    } finally {
        client.close();
    }

    return detected;
}

async function getPackageManager(forcePackageKit = false) {
    if (packageManager !== null)
        return packageManager;

    const [unsupported, hasDnf5Daemon, hasPackageKit] = await Promise.all([
        isImmutableOS(),
        detectDnf5Daemon(),
        detectPackageKit(),
    ]);

    if (unsupported)
        throw createPackageManagerError("UnsupportedError", "Cockpit does not support installing additional packages on immutable operating systems");

    if (hasDnf5Daemon && !forcePackageKit) {
        packageManager = createDnf5DaemonManager();
        return packageManager;
    }

    if (hasPackageKit) {
        packageManager = createPackageKitManager();
        return packageManager;
    }

    throw createPackageManagerError("NotFoundError", "No package manager found");
}

function resetDnf5Connection() {
    if (dnf5Client)
        dnf5Client.close();
    dnf5Client = null;
}

function packageKitDbusClient() {
    if (!packageKitClient) {
        packageKitClient = cockpit.dbus("org.freedesktop.PackageKit", { superuser: "try", track: true });
        packageKitClient.addEventListener("close", () => {
            packageKitClient = null;
        });
    }

    return packageKitClient;
}

function packageKitCall(objectPath, iface, method, args, options) {
    return packageKitDbusClient().call(objectPath, iface, method, args, options);
}

function watchPackageKitTransaction(transactionPath, signalHandlers, notifyHandler) {
    const subscriptions = [];
    const client = packageKitDbusClient();

    function onClose(_event, error) {
        if (signalHandlers.ErrorCode)
            signalHandlers.ErrorCode("close", formatError(error) || "PackageKit-Verbindung wurde getrennt.");
        if (signalHandlers.Finished)
            signalHandlers.Finished(PACKAGEKIT_ENUM.EXIT_CANCELLED);
    }

    function onNotify(reply) {
        const iface = reply?.detail?.[transactionPath]?.[PACKAGEKIT_TRANSACTION_INTERFACE];
        if (iface)
            notifyHandler(iface, transactionPath);
    }

    client.addEventListener("close", onClose);

    if (signalHandlers) {
        Object.keys(signalHandlers).forEach(handler => {
            subscriptions.push(client.subscribe({
                interface: PACKAGEKIT_TRANSACTION_INTERFACE,
                path: transactionPath,
                member: handler,
            }, (_path, _iface, _signal, args) => signalHandlers[handler](...args)));
        });
    }

    if (notifyHandler) {
        subscriptions.push(client.watch(transactionPath));
        client.addEventListener("notify", onNotify);
    }

    subscriptions.push(client.subscribe({
        interface: PACKAGEKIT_TRANSACTION_INTERFACE,
        path: transactionPath,
        member: "Finished",
    }, () => {
        subscriptions.forEach(subscription => subscription.remove());
        client.removeEventListener("close", onClose);
        if (notifyHandler)
            client.removeEventListener("notify", onNotify);
    }));

    return subscriptions[subscriptions.length - 1];
}

function packageKitTransaction(method, arglist, signalHandlers, notifyHandler) {
    return packageKitCall("/org/freedesktop/PackageKit", "org.freedesktop.PackageKit", "CreateTransaction", [])
        .then(([transactionPath]) => {
            if (!signalHandlers && !notifyHandler)
                return transactionPath;

            watchPackageKitTransaction(transactionPath, signalHandlers, notifyHandler);
            if (!method)
                return transactionPath;

            return packageKitCall(transactionPath, PACKAGEKIT_TRANSACTION_INTERFACE, method, arglist)
                .then(() => transactionPath);
        });
}

function packageKitCancellableTransaction(method, arglist, progressCallback, signalHandlers = {}) {
    return new Promise((resolve, reject) => {
        let cancelled = false;
        let status;
        let allowWaitStatus = false;
        const progressData = {
            waiting: false,
            percentage: 0,
            cancel: null,
        };

        function changed(props, transactionPath) {
            function cancel() {
                cancelled = true;
                packageKitCall(transactionPath, PACKAGEKIT_TRANSACTION_INTERFACE, "Cancel", []).catch(() => {});
            }

            if (!progressCallback)
                return;

            if ("Status" in props)
                status = props.Status;
            progressData.waiting = allowWaitStatus && (status === PACKAGEKIT_ENUM.STATUS_WAIT || status === PACKAGEKIT_ENUM.STATUS_WAITING_FOR_LOCK);
            if ("AllowCancel" in props)
                progressData.cancel = props.AllowCancel ? cancel : null;
            if ("Percentage" in props && props.Percentage <= 100)
                progressData.percentage = props.Percentage;

            progressCallback(progressData);
        }

        window.setTimeout(() => {
            allowWaitStatus = true;
            changed({});
        }, 1000);

        packageKitTransaction(method, arglist, {
            ...signalHandlers,
            ErrorCode: (code, detail) => {
                progressCallback = null;
                reject(new Error(cancelled ? "cancelled" : detail || code));
            },
            Finished: exit => {
                progressCallback = null;
                if (cancelled || exit === PACKAGEKIT_ENUM.EXIT_CANCELLED)
                    reject(new Error("cancelled"));
                else
                    resolve(exit);
            },
        }, changed).catch(error => {
            progressCallback = null;
            reject(error);
        });
    });
}

function packageProgressMessage(prefix, progress) {
    if (progress?.waiting)
        return "Warte auf den Abschluss anderer Paketverwaltungsaktionen";
    if (!progress?.package)
        return prefix;

    if (progress.info === INSTALL_PROGRESS_TYPE.DOWNLOADING)
        return `Download läuft: ${progress.package}`;
    if (progress.info === INSTALL_PROGRESS_TYPE.REMOVING)
        return `Wird entfernt: ${progress.package}`;

    return `Installation läuft: ${progress.package}`;
}

function formatInstallError(error) {
    const message = formatError(error);
    if (/ServiceUnknown|not-found|not supported|No package manager/i.test(message))
        return "Keine Paketverwaltung verfügbar. Software kann über diese Seite nicht installiert werden.";
    if (/immutable|read-only|只读|不可变/i.test(message))
        return "Auf diesem System können keine zusätzlichen Pakete im unveränderlichen /usr installiert werden.";
    return message;
}

async function checkMissingPackages(packageNames, progressCallback) {
    const data = {
        download_size: 0,
        missing_ids: [],
        missing_names: [],
        unavailable_names: [],
        extra_names: [],
        remove_names: [],
    };

    await packageKitCancellableTransaction("RefreshCache", [false], progressCallback);

    const installedNames = new Set();
    await packageKitCancellableTransaction("Resolve", [
        PACKAGEKIT_ENUM.FILTER_ARCH | PACKAGEKIT_ENUM.FILTER_NOT_SOURCE | PACKAGEKIT_ENUM.FILTER_NEWEST,
        packageNames,
    ], progressCallback, {
        Package: (_info, packageId) => {
            const parts = packageId.split(";");
            const repos = parts[3]?.split(":") || [];
            if (repos.includes("installed")) {
                installedNames.add(parts[0]);
                return;
            }

            data.missing_ids.push(packageId);
            data.missing_names.push(parts[0]);
        },
    });

    packageNames.forEach(name => {
        if (!installedNames.has(name) && !data.missing_names.includes(name))
            data.unavailable_names.push(name);
    });

    if (data.missing_ids.length > 0 && data.unavailable_names.length === 0) {
        const installIds = [];
        await packageKitCancellableTransaction("InstallPackages", [
            PACKAGEKIT_ENUM.TRANSACTION_FLAG_SIMULATE,
            data.missing_ids,
        ], progressCallback, {
            Package: (info, packageId) => {
                const name = packageId.split(";")[0];
                if (info === PACKAGEKIT_ENUM.INFO_REMOVING) {
                    data.remove_names.push(name);
                } else if (info === PACKAGEKIT_ENUM.INFO_INSTALLING || info === PACKAGEKIT_ENUM.INFO_UPDATING) {
                    installIds.push(packageId);
                    if (!data.missing_names.includes(name))
                        data.extra_names.push(name);
                }
            },
        });

        if (installIds.length > 0) {
            await packageKitCancellableTransaction("GetDetails", [installIds], progressCallback, {
                Details: (...args) => {
                    const details = args[0];
                    const size = details?.size?.v || args[5]?.v || args[5];
                    if (Number.isFinite(Number(size)))
                        data.download_size += Number(size);
                },
            });
        }
    }

    data.missing_names.sort();
    data.extra_names.sort();
    data.remove_names.sort();
    return data;
}

async function installMissingPackages(data, progressCallback) {
    if (!data || data.missing_ids.length === 0)
        return;

    let lastProgress = null;
    let lastInfo = 0;
    let lastName = "";

    function reportProgress() {
        if (!lastProgress)
            return;

        progressCallback({
            waiting: lastProgress.waiting,
            percentage: lastProgress.percentage,
            cancel: lastProgress.cancel,
            info: PACKAGEKIT_INSTALL_PROGRESS_MAP[lastInfo],
            package: lastName,
        });
    }

    await packageKitCancellableTransaction("InstallPackages", [0, data.missing_ids], progress => {
        lastProgress = progress;
        reportProgress();
    }, {
        Package: (info, packageId) => {
            lastInfo = info;
            lastName = packageId.split(";")[0];
            reportProgress();
        },
    });
}

function createPackageKitManager() {
    return {
        name: "packagekit",
        check_missing_packages: checkMissingPackages,
        install_missing_packages: installMissingPackages,
    };
}

function dnf5DbusClient() {
    if (!dnf5Client) {
        dnf5Client = cockpit.dbus("org.rpm.dnf.v0", { superuser: "try", track: true });
        dnf5Client.addEventListener("close", () => {
            dnf5Client = null;
        });
    }

    return dnf5Client;
}

function dnf5Call(objectPath, iface, method, args, options) {
    return dnf5DbusClient().call(objectPath, iface, method, args, options);
}

async function openDnf5Session() {
    const [session] = await dnf5Call("/org/rpm/dnf/v0", "org.rpm.dnf.v0.SessionManager", "open_session", [{}]);
    return session;
}

function closeDnf5Session(session) {
    return dnf5Call("/org/rpm/dnf/v0", "org.rpm.dnf.v0.SessionManager", "close_session", [session]);
}

async function withDnf5Session(executor, signalHandler) {
    let session = null;
    let subscription = null;
    const client = dnf5DbusClient();

    if (signalHandler)
        subscription = client.subscribe({}, signalHandler);

    try {
        session = await openDnf5Session();
        return await executor(session);
    } finally {
        if (session)
            await closeDnf5Session(session);
        if (subscription)
            subscription.remove();
    }
}

function dnf5PackageName(pkg) {
    return pkg?.name?.v || "";
}

function createDnf5DaemonManager() {
    async function refresh(_force, _progressCallback) {
        await withDnf5Session(async session => {
            await dnf5Call(session, "org.rpm.dnf.v0.Base", "read_all_repos", []);
            const [, resolveResult] = await dnf5Call(session, "org.rpm.dnf.v0.Goal", "resolve", [{}]);
            if (resolveResult !== 0) {
                const [problem] = await dnf5Call(session, "org.rpm.dnf.v0.Goal", "get_transaction_problems_string", []);
                throw createPackageManagerError("ResolveError", `Resolving read_all_repos failed with result=${resolveResult} - ${problem}`);
            }
            await dnf5Call(session, "org.rpm.dnf.v0.Goal", "do_transaction", [{}]);
        });
    }

    async function checkMissingPackagesDnf5(packageNames, progressCallback) {
        const data = {
            download_size: 0,
            missing_ids: [],
            missing_names: [],
            unavailable_names: [],
            extra_names: [],
            remove_names: [],
        };

        if (packageNames.length === 0)
            return data;

        async function resolve(session) {
            const installedNames = new Set();
            const seenNames = new Set();
            const [results] = await dnf5Call(session, "org.rpm.dnf.v0.rpm.Rpm", "list", [{
                package_attrs: { t: "as", v: ["name", "is_installed"] },
                scope: { t: "s", v: "all" },
                patterns: { t: "as", v: packageNames },
            }]);

            for (const pkg of results || []) {
                const name = dnf5PackageName(pkg);
                if (!name || seenNames.has(name))
                    continue;

                if (pkg.is_installed?.v) {
                    installedNames.add(name);
                } else {
                    data.missing_ids.push(name);
                    data.missing_names.push(name);
                }

                seenNames.add(name);
            }

            packageNames.forEach(name => {
                if (!installedNames.has(name) && !data.missing_names.includes(name))
                    data.unavailable_names.push(name);
            });
        }

        async function simulate(session) {
            if (data.missing_ids.length === 0 || data.unavailable_names.length > 0)
                return;

            await dnf5Call(session, "org.rpm.dnf.v0.rpm.Rpm", "install", [packageNames, {}]);
            const [transactionItems, result] = await dnf5Call(session, "org.rpm.dnf.v0.Goal", "resolve", [{}]);
            if (result !== 0) {
                const [problem] = await dnf5Call(session, "org.rpm.dnf.v0.Goal", "get_transaction_problems_string", []);
                throw createPackageManagerError("ResolveError", `Resolving install failed with result=${result}. ${problem}`);
            }

            for (const transactionItem of transactionItems || []) {
                const [objectType, action, reason,, pkg] = transactionItem;
                const name = dnf5PackageName(pkg);
                if (objectType !== "Package" || !name)
                    continue;

                data.download_size += Number(pkg.download_size?.v || 0);
                if (reason === "Dependency" && !data.missing_names.includes(name))
                    data.extra_names.push(name);
                if (action === "Replaced" && !data.remove_names.includes(name))
                    data.remove_names.push(name);
            }

            await dnf5Call(session, "org.rpm.dnf.v0.Goal", "reset", []);
        }

        function signalEmitted() {
            if (progressCallback) {
                progressCallback({
                    waiting: false,
                    percentage: 0,
                    cancel: null,
                });
            }
        }

        await refresh(false);
        await withDnf5Session(async session => {
            await resolve(session);
            await simulate(session);
        }, signalEmitted);

        data.missing_names.sort();
        data.extra_names.sort();
        data.remove_names.sort();
        return data;
    }

    async function installMissingPackagesDnf5(data, progressCallback) {
        if (!data || data.missing_ids.length === 0)
            return;

        let lastInfo = INSTALL_PROGRESS_TYPE.INSTALLING;
        let lastProgress = 0;
        let lastName = "";
        let totalPackages = 0;

        function signalEmitted(_path, _iface, signal, args) {
            switch (signal) {
            case "download_add_new":
                lastInfo = INSTALL_PROGRESS_TYPE.DOWNLOADING;
                lastName = args[2] || "";
                break;
            case "download_progress":
                lastInfo = INSTALL_PROGRESS_TYPE.DOWNLOADING;
                break;
            case "download_end":
                lastInfo = INSTALL_PROGRESS_TYPE.INSTALLING;
                lastName = "";
                break;
            case "transaction_before_begin":
                totalPackages = Number(args[1] || 0);
                lastInfo = INSTALL_PROGRESS_TYPE.INSTALLING;
                break;
            case "transaction_elem_progress":
                lastName = args[1] || "";
                lastProgress = totalPackages ? Number(args[2] || 0) / totalPackages * 100 : 0;
                break;
            }

            if (progressCallback) {
                progressCallback({
                    cancel: null,
                    info: lastInfo,
                    package: lastName,
                    percentage: lastProgress,
                    waiting: false,
                });
            }
        }

        await withDnf5Session(async session => {
            try {
                await dnf5Call(session, "org.rpm.dnf.v0.rpm.Rpm", "install", [data.missing_names, {}]);
                const [, resolveResult] = await dnf5Call(session, "org.rpm.dnf.v0.Goal", "resolve", [{}]);
                if (resolveResult !== 0) {
                    const [problem] = await dnf5Call(session, "org.rpm.dnf.v0.Goal", "get_transaction_problems_string", []);
                    throw createPackageManagerError("ResolveError", `Resolving install failed with result=${resolveResult} ${problem}`);
                }
                await dnf5Call(session, "org.rpm.dnf.v0.Goal", "do_transaction", [{}]);
            } catch (error) {
                console.warn("install error", error);
            }
        }, signalEmitted);
    }

    return {
        name: "dnf5daemon",
        check_missing_packages: checkMissingPackagesDnf5,
        install_missing_packages: installMissingPackagesDnf5,
        refresh,
    };
}

function formatError(error) {
    if (typeof error === "string")
        return error;

    if (error?.message)
        return error.message;

    if (error?.problem)
        return `${error.problem}${error.exit_status ? ` (exit ${error.exit_status})` : ""}`;

    try {
        return JSON.stringify(error, null, 2);
    } catch (_error) {
        return "Befehl fehlgeschlagen; das Fehlerobjekt konnte nicht ausgewertet werden.";
    }
}

function unwrapVariant(value) {
    let current = value;
    while (
        current &&
        typeof current === "object" &&
        Object.prototype.hasOwnProperty.call(current, "v") &&
        Object.keys(current).length === 1
    ) {
        current = current.v;
    }
    return current;
}

function normalizePromptText(value, fallback = "") {
    const text = String(unwrapVariant(value) || "").replace(/^\[sudo] /, "").trim();
    if (!text)
        return fallback;
    return text.charAt(0).toUpperCase() + text.slice(1);
}

function getSuperuserMethods() {
    const methods = unwrapVariant(state.superuserProxy?.Methods);
    if (!methods || typeof methods !== "object")
        return [];

    return Object.keys(methods).map(id => {
        const definition = unwrapVariant(methods[id]);
        const label = normalizePromptText(unwrapVariant(definition?.label), id);
        return { id, label: label || id };
    });
}

function resetSuperuserDialog() {
    if (typeof state.superuserDialog.cleanup === "function")
        state.superuserDialog.cleanup();

    state.superuserDialog = {
        open: false,
        methods: [],
        selectedMethod: "",
        message: "",
        prompt: "",
        value: "",
        echo: false,
        error: "",
        errorTone: "warning",
        inProgress: false,
        promptSeen: false,
        cleanup: null,
        closeAfterSuccess: false,
    };
}

function setText(id, text) {
    const element = document.getElementById(id);
    if (element)
        element.textContent = text;
}

// Status is plain text next to the section title, not a Label pill; Cockpit
// reserves labels for counts and tags, not for "running/loading".
function setStatusText(id, text, tone = "neutral") {
    const element = document.getElementById(id);
    if (!element)
        return;

    element.textContent = text || "";
    element.classList.remove("tone-success", "tone-warning", "tone-danger", "tone-loading");
    if (["success", "warning", "danger", "loading"].includes(tone))
        element.classList.add(`tone-${tone}`);
}

const ALERT_ICONS = {
    success: '<path d="M504 256c0 136.967-111.033 248-248 248S8 392.967 8 256 119.033 8 256 8s248 111.033 248 248zM227.314 387.314l184-184c6.248-6.248 6.248-16.379 0-22.627l-22.627-22.627c-6.248-6.249-16.379-6.249-22.628 0L216 308.118l-70.059-70.059c-6.248-6.248-16.379-6.248-22.628 0l-22.627 22.627c-6.248 6.248-6.248 16.379 0 22.627l104 104c6.249 6.249 16.379 6.249 22.628.001z"/>',
    warning: '<path d="M569.517 440.013C587.975 472.007 564.806 512 527.94 512H48.054c-36.937 0-59.999-40.055-41.577-71.987L246.423 23.985c18.467-32.009 64.72-31.951 83.154 0l239.94 416.028zM288 354c-25.405 0-46 20.595-46 46s20.595 46 46 46 46-20.595 46-46-20.595-46-46-46zm-43.673-165.346l7.418 136c.347 6.364 5.609 11.346 11.982 11.346h48.546c6.373 0 11.635-4.982 11.982-11.346l7.418-136c.375-6.874-5.098-12.654-11.982-12.654h-63.383c-6.884 0-12.356 5.78-11.981 12.654z"/>',
    danger: '<path d="M504 256c0 136.997-111.043 248-248 248S8 392.997 8 256C8 119.083 119.043 8 256 8s248 111.083 248 248zm-248 50c-25.405 0-46 20.595-46 46s20.595 46 46 46 46-20.595 46-46-20.595-46-46-46zm-43.673-165.346l7.418 136c.347 6.364 5.609 11.346 11.982 11.346h48.546c6.373 0 11.635-4.982 11.982-11.346l7.418-136c.375-6.874-5.098-12.654-11.982-12.654h-63.383c-6.884 0-12.356 5.78-11.981 12.654z"/>',
    info: '<path d="M256 8C119.043 8 8 119.083 8 256c0 136.997 111.043 248 248 248s248-111.003 248-248C504 119.083 392.957 8 256 8zm0 110c23.196 0 42 18.804 42 42s-18.804 42-42 42-42-18.804-42-42 18.804-42 42-42zm56 254c0 6.627-5.373 12-12 12h-88c-6.627 0-12-5.373-12-12v-24c0-6.627 5.373-12 12-12h12v-64h-12c-6.627 0-12-5.373-12-12v-24c0-6.627 5.373-12 12-12h64c6.627 0 12 5.373 12 12v100h12c6.627 0 12-5.373 12 12v24z"/>',
};

const ALERT_VARIANT_LABEL = { success: "Erfolg:", warning: "Warnung:", danger: "Fehler:", info: "Hinweis:" };

// Standard PF inline Alert, matching cockpit-components-inline-notification:
// one line title, optional detail behind a "show more" link.
function setAlert(id, { title = "", detail = "", variant = "info", inline = true } = {}) {
    const slot = document.getElementById(id);
    if (!slot)
        return;

    slot.replaceChildren();
    if (!title && !detail) {
        slot.hidden = true;
        return;
    }

    slot.hidden = false;
    const alert = document.createElement("div");
    alert.className = `pf-v6-c-alert${inline ? " pf-m-inline" : ""} pf-m-${variant}`;

    const icon = document.createElement("div");
    icon.className = "pf-v6-c-alert__icon";
    icon.innerHTML = `<svg class="pf-v6-svg" viewBox="0 0 512 512" fill="currentColor" aria-hidden="true" width="1em" height="1em">${ALERT_ICONS[variant] || ALERT_ICONS.info}</svg>`;
    alert.append(icon);

    const heading = document.createElement("h4");
    heading.className = "pf-v6-c-alert__title";
    const sr = document.createElement("span");
    sr.className = "pf-v6-screen-reader";
    sr.textContent = ALERT_VARIANT_LABEL[variant] || "";
    heading.append(sr, document.createTextNode(title || detail));
    alert.append(heading);

    if (title && detail) {
        const description = document.createElement("div");
        description.className = "pf-v6-c-alert__description";
        const paragraph = document.createElement("p");
        paragraph.textContent = detail;
        paragraph.hidden = true;
        const toggle = document.createElement("button");
        toggle.type = "button";
        toggle.className = "pf-v6-c-button pf-m-link pf-m-inline alert-link";
        toggle.textContent = "Details anzeigen";
        toggle.addEventListener("click", () => {
            paragraph.hidden = !paragraph.hidden;
            toggle.textContent = paragraph.hidden ? "Details anzeigen" : "Details ausblenden";
        });
        description.append(paragraph);
        heading.append(" ", toggle);
        alert.append(description);
    } else if (detail) {
        const description = document.createElement("div");
        description.className = "pf-v6-c-alert__description";
        description.textContent = detail;
        alert.append(description);
    }

    slot.append(alert);
}

function getCurrentFirewallTool() {
    return REQUIRED_TOOLS[state.firewallBackend] || REQUIRED_TOOLS.ufw;
}

function renderFirewallInstallState(missing) {
    const tool = getCurrentFirewallTool();
    const content = getElement("firewall-settings-content");
    const installState = getElement("firewall-install-state");
    const title = getElement("firewall-install-title");
    const copy = getElement("firewall-install-copy");
    const action = getElement("firewall-install-action");

    if (content)
        content.hidden = Boolean(missing);
    if (installState)
        installState.hidden = !missing;

    if (!missing)
        return;

    setStatusText("firewall-status-pill", "Nicht installiert", isWritable() ? "warning" : "neutral");
    if (title)
        title.textContent = tool.installTitle;
    if (copy)
        copy.textContent = isWritable() ? tool.installCopy : `${tool.installCopy} Zum Installieren von Software sind Administratorrechte erforderlich.`;
    if (action) {
        action.textContent = tool.installTitle;
        action.dataset.installTool = tool.id;
    }
}

function renderFail2BanInstallState(missing) {
    const content = getElement("fail2ban-settings-content");
    const installState = getElement("fail2ban-install-state");
    const copy = installState?.querySelector(".pf-v6-c-empty-state__body");

    if (content)
        content.hidden = Boolean(missing);
    if (installState)
        installState.hidden = !missing;

    if (copy)
        copy.textContent = isWritable()
            ? "Installiere Fail2Ban, um Jails anzuzeigen und gesperrte IP-Adressen zu verwalten. "
            : "Installiere Fail2Ban, um Jails anzuzeigen und gesperrte IP-Adressen zu verwalten. Zum Installieren von Software sind Administratorrechte erforderlich.";

    if (missing)
        setStatusText("fail2ban-service-pill", "Nicht installiert", isWritable() ? "warning" : "neutral");
}

function resetInstallDialog(options = {}) {
    if (options.cancel !== false && typeof state.installDialog.cancel === "function")
        state.installDialog.cancel();

    state.installDialog = {
        open: false,
        toolId: "",
        packageNames: [],
        data: null,
        checking: false,
        busy: false,
        progressMessage: "",
        error: "",
        cancel: null,
    };
}

function updateInstallDialog(patch) {
    state.installDialog = {
        ...state.installDialog,
        ...patch,
    };
    renderInstallDialog();
}

function appendPackageList(container, label, items) {
    if (!items?.length)
        return;

    const section = document.createElement("div");
    section.className = "security-package-list";
    const heading = document.createElement("p");
    heading.textContent = label;
    const list = document.createElement("ul");
    list.className = "package-list-ct";

    items.forEach(item => {
        const listItem = document.createElement("li");
        listItem.textContent = item;
        list.append(listItem);
    });

    section.append(heading, list);
    container.append(section);
}

function renderInstallDialog() {
    const dialog = getElement("security-install-dialog");
    const title = getElement("security-install-title");
    const alert = getElement("security-install-alert");
    const body = getElement("security-install-body");
    const footerMessage = getElement("security-install-footer-message");
    const submit = getElement("security-install-submit");
    const cancel = getElement("security-install-cancel");
    const close = getElement("security-install-close");

    if (!dialog || !title || !alert || !body || !footerMessage || !submit || !cancel || !close)
        return;

    const current = state.installDialog;
    const tool = REQUIRED_TOOLS[current.toolId] || REQUIRED_TOOLS.ufw;
    dialog.hidden = !current.open;
    if (!current.open)
        return;

    title.textContent = "Software installieren";
    setAlert("security-install-alert", current.error ? { title: current.error, variant: "danger" } : {});

    body.replaceChildren();
    const text = document.createElement("p");
    const packageNames = (current.packageNames?.length ? current.packageNames : tool.packages).join(", ");
    const packageName = document.createElement("strong");
    packageName.textContent = packageNames;
    text.append(packageName, " wird installiert.");
    body.append(text);

    appendPackageList(body, "Zusätzliche Pakete:", current.data?.extra_names || []);
    appendPackageList(body, "Wird entfernt:", current.data?.remove_names || []);

    let footerText = current.progressMessage;
    if (!footerText && current.data?.download_size)
        footerText = `Gesamtgröße: ${cockpit.format_bytes(current.data.download_size)}`;

    footerMessage.hidden = !footerText;
    footerMessage.replaceChildren();
    if (footerText) {
        footerMessage.append(document.createTextNode(footerText));
        if (current.checking || current.busy) {
            const spinner = document.createElement("span");
            spinner.className = "pf-v6-c-spinner pf-m-sm";
            spinner.setAttribute("role", "progressbar");
            spinner.setAttribute("aria-label", "Wird geladen");
            footerMessage.append(spinner);
        }
    }

    submit.disabled = current.checking || current.busy || !current.data || Boolean(current.error && !current.data);
    submit.textContent = current.busy ? "Installation läuft..." : "Installieren";
    cancel.disabled = false;
    close.disabled = false;
}

async function resolveToolInstallPackages(manager, tool, progressCallback) {
    const candidates = tool.packageCandidates?.length ? tool.packageCandidates : [tool.packages];
    let lastResult = null;
    const unavailableNames = new Set();

    for (const packageNames of candidates) {
        updateInstallDialog({ packageNames });
        const data = await manager.check_missing_packages(packageNames, progressCallback);
        lastResult = { packageNames, data };
        if (!data.unavailable_names.length)
            return lastResult;

        data.unavailable_names.forEach(name => unavailableNames.add(name));
    }

    if (lastResult && unavailableNames.size > 0)
        lastResult.data.unavailable_names = Array.from(unavailableNames);

    return lastResult;
}

async function openInstallDialog(toolId) {
    const tool = REQUIRED_TOOLS[toolId];
    if (!tool || !isWritable())
        return;

    if (await checkToolInstalled(toolId, { force: true })) {
        if (toolId === "fail2ban")
            refreshFail2BanStatus();
        else
            refreshFirewallStatus();
        return;
    }

    resetInstallDialog();
    state.installDialog = {
        open: true,
        toolId,
        packageNames: tool.packages,
        data: null,
        checking: true,
        busy: false,
        progressMessage: "Installierte Software wird geprüft",
        error: "",
        cancel: null,
    };
    renderInstallDialog();

    try {
        const manager = await getPackageManager();
        const result = await resolveToolInstallPackages(manager, tool, progress => {
            updateInstallDialog({
                progressMessage: progress?.waiting ? "Warte auf den Abschluss anderer Paketverwaltungsaktionen" : "Installierte Software wird geprüft",
                cancel: progress?.cancel || null,
            });
        });
        const data = result?.data || { unavailable_names: tool.packages };

        updateInstallDialog({
            packageNames: result?.packageNames || tool.packages,
            data: data.unavailable_names.length ? null : data,
            checking: false,
            progressMessage: "",
            cancel: null,
            error: data.unavailable_names.length
                ? `${data.unavailable_names[0]} ist in keinem verfügbaren Paketarchiv enthalten.`
                : "",
        });
    } catch (error) {
        if (formatError(error) === "cancelled") {
            closeInstallDialog();
            return;
        }

        updateInstallDialog({
            checking: false,
            progressMessage: "",
            cancel: null,
            error: formatInstallError(error) || "Die Paketverwaltung des Systems ist nicht verfügbar.",
        });
    }
}

function closeInstallDialog(options = {}) {
    resetInstallDialog(options);
    renderInstallDialog();
}

async function handleInstallDialogSubmit() {
    const current = state.installDialog;
    if (!isWritable() || !current.open || current.checking || current.busy || !current.data)
        return;

    const toolId = current.toolId;
    updateInstallDialog({
        busy: true,
        error: "",
        progressMessage: "Softwarepakete werden installiert",
    });

    try {
        const manager = await getPackageManager();
        await manager.install_missing_packages(current.data, progress => {
            updateInstallDialog({
                progressMessage: packageProgressMessage("Softwarepakete werden installiert", progress),
                cancel: progress?.cancel || null,
            });
        });
    } catch (error) {
        if (formatError(error) === "cancelled") {
            closeInstallDialog();
            return;
        }

        updateInstallDialog({
            busy: false,
            progressMessage: "",
            cancel: null,
            error: formatInstallError(error) || "Paketinstallation fehlgeschlagen.",
        });
        return;
    }

    closeInstallDialog({ cancel: false });
    await checkToolInstalled(toolId, { force: true });
    if (toolId === "fail2ban")
        await refreshFail2BanStatus();
    else
        await refreshFirewallStatus();
    refreshSecurityLogs();
}

function summarizeOutput(text, ok = true) {
    const lines = String(text || "")
        .split(/\r?\n/)
        .map(line => line.trim())
        .filter(Boolean);

    if (!lines.length)
        return ok ? "Befehl erfolgreich ausgeführt. Keine weitere Ausgabe." : "Befehl fehlgeschlagen.";

    const combined = lines.join(" ");
    if (/permission denied to socket/i.test(combined))
        return "Administratorrechte erforderlich für den Zugriff auf den Fail2Ban-Socket.";

    if (/you must be root/i.test(combined))
        return "Dieser Befehl benötigt Root-Rechte.";

    if (/not found|command not found|No such file/i.test(combined))
        return "Befehl oder Komponente nicht gefunden. Bitte die Installation auf dem Zielrechner prüfen.";

    return lines[0];
}

function renderDetailList(id, items, emptyText = "Keine Details verfügbar.") {
    const list = document.getElementById(id);
    if (!list)
        return;

    list.replaceChildren();

    const entries = items.length ? items : [["Status", emptyText]];
    const fragment = document.createDocumentFragment();

    entries.forEach(([label, value]) => {
        const group = document.createElement("div");
        group.className = "pf-v6-c-description-list__group";

        const dt = document.createElement("dt");
        dt.className = "pf-v6-c-description-list__term";
        const termText = document.createElement("span");
        termText.className = "pf-v6-c-description-list__text";
        termText.textContent = label;
        dt.append(termText);

        const dd = document.createElement("dd");
        dd.className = "pf-v6-c-description-list__description";
        const descriptionText = document.createElement("div");
        descriptionText.className = "pf-v6-c-description-list__text";
        descriptionText.textContent = value;
        dd.append(descriptionText);

        group.append(dt, dd);
        fragment.append(group);
    });

    list.append(fragment);
}

function buildEmptyState(text) {
    const wrapper = document.createElement("div");
    wrapper.className = "pf-v6-c-empty-state pf-m-sm";

    const content = document.createElement("div");
    content.className = "pf-v6-c-empty-state__content";

    const icon = document.createElement("div");
    icon.className = "pf-v6-c-empty-state__icon";
    icon.innerHTML = '<svg class="pf-v6-svg" viewBox="0 0 512 512" fill="currentColor" aria-hidden="true" width="1em" height="1em"><path d="M505 442.7L405.3 343c-4.5-4.5-10.6-7-17-7H372c27.6-35.3 44-79.7 44-128C416 93.1 322.9 0 208 0S0 93.1 0 208s93.1 208 208 208c48.3 0 92.7-16.4 128-44v16.3c0 6.4 2.5 12.5 7 17l99.7 99.7c9.4 9.4 24.6 9.4 33.9 0l28.3-28.3c9.4-9.4 9.4-24.6.1-34zM208 336c-70.7 0-128-57.2-128-128 0-70.7 57.2-128 128-128 70.7 0 128 57.2 128 128 0 70.7-57.2 128-128 128z"/></svg>';

    const title = document.createElement("h4");
    title.className = "pf-v6-c-title pf-m-lg";
    title.textContent = text;

    content.append(icon, title);
    wrapper.append(content);
    return wrapper;
}

function renderTable(headId, bodyId, columns, rows, emptyText) {
    const head = document.getElementById(headId);
    const body = document.getElementById(bodyId);

    if (!head || !body)
        return;

    const normalizedRows = rows.map(row => Array.isArray(row) ? { cells: row } : row);
    const hasActions = normalizedRows.some(row => row.delete);
    const table = body.closest("table");
    const headRow = document.createElement("tr");
    headRow.className = "pf-v6-c-table__tr";
    columns.forEach(column => {
        const th = document.createElement("th");
        th.className = "pf-v6-c-table__th";
        th.scope = "col";
        th.textContent = column;
        headRow.append(th);
    });
    if (hasActions) {
        const th = document.createElement("th");
        th.className = "pf-v6-c-table__th";
        th.scope = "col";
        th.textContent = "Aktionen";
        headRow.append(th);
    }

    head.replaceChildren(headRow);
    body.replaceChildren();
    table?.classList.toggle("ct-table-empty", !normalizedRows.length);

    if (!normalizedRows.length) {
        const row = document.createElement("tr");
        row.className = "pf-v6-c-table__tr";
        const cell = document.createElement("td");
        cell.className = "pf-v6-c-table__td data-table__empty-cell";
        cell.colSpan = columns.length + (hasActions ? 1 : 0);
        cell.append(buildEmptyState(emptyText));
        row.append(cell);
        body.append(row);
        return;
    }

    normalizedRows.forEach(row => {
        const tr = document.createElement("tr");
        tr.className = "pf-v6-c-table__tr";

        row.cells.forEach((cell, index) => {
            const element = document.createElement(index === 0 ? "th" : "td");
            if (index === 0) {
                element.scope = "row";
                element.className = "pf-v6-c-table__th data-table__primary";
            } else {
                element.className = "pf-v6-c-table__td";
            }
            element.dataset.label = columns[index] || "";
            element.textContent = cell;
            tr.append(element);
        });

        if (hasActions) {
            const actionCell = document.createElement("td");
            actionCell.className = "pf-v6-c-table__td data-table__action";
            actionCell.dataset.label = "Aktionen";

            if (row.delete && !row.delete.disabled) {
                const button = document.createElement("button");
                button.type = "button";
                button.className = "pf-v6-c-button pf-m-link pf-m-inline data-table__delete";
                button.textContent = row.delete.label || "Löschen";
                button.addEventListener("click", () => {
                    deleteFirewallRule(row.delete);
                });
                actionCell.append(button);
            } else if (row.delete?.disabled) {
                const hint = document.createElement("span");
                hint.className = "data-table__hint";
                hint.textContent = "Extern verwaltet";
                actionCell.append(hint);
            }

            tr.append(actionCell);
        }

        body.append(tr);
    });
}

function getFirewallRuleTotalPages() {
    return Math.max(1, Math.ceil(state.firewallRules.rows.length / state.firewallRules.pageSize));
}

function updateFirewallRulePageOptions(totalPages) {
    const options = document.getElementById("firewall-rules-page-options");
    if (!options)
        return;

    const fragment = document.createDocumentFragment();
    for (let page = 1; page <= totalPages; page++) {
        const option = document.createElement("option");
        option.value = String(page);
        option.label = `Seite ${page}`;
        fragment.append(option);
    }
    options.replaceChildren(fragment);
}

function renderFirewallRulePagination(totalRows) {
    const container = document.getElementById("firewall-rules-pagination");
    const meta = document.getElementById("firewall-rules-page-meta");
    const prev = document.getElementById("firewall-rules-prev");
    const next = document.getElementById("firewall-rules-next");
    const jumpInput = document.getElementById("firewall-rules-page-jump");

    if (!container || !meta || !prev || !next)
        return;

    const totalPages = Math.max(1, Math.ceil(totalRows / state.firewallRules.pageSize));
    container.hidden = totalRows <= state.firewallRules.pageSize;
    meta.textContent = `Seite ${state.firewallRules.page} / ${totalPages}`;
    prev.disabled = state.firewallRules.page <= 1;
    next.disabled = state.firewallRules.page >= totalPages;
    updateFirewallRulePageOptions(totalPages);

    if (jumpInput) {
        jumpInput.value = String(state.firewallRules.page);
        jumpInput.setAttribute("aria-label", `Zur Seite wechseln; Seiten insgesamt: ${totalPages}`);
    }
}

function renderFirewallRulesTable() {
    const { columns, rows, emptyText, page, pageSize } = state.firewallRules;
    const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
    const currentPage = Math.min(Math.max(1, page), totalPages);
    state.firewallRules.page = currentPage;

    const start = (currentPage - 1) * pageSize;
    const pageRows = rows.slice(start, start + pageSize);
    renderTable("firewall-rules-head", "firewall-rules-body", columns, pageRows, emptyText);
    renderFirewallRulePagination(rows.length);
}

function jumpToFirewallRulesPage(value) {
    const pageText = String(value || "").trim();
    if (!/^\d+$/.test(pageText)) {
        renderFirewallRulesTable();
        return;
    }

    const totalPages = getFirewallRuleTotalPages();
    const nextPage = Math.min(Math.max(1, Number(pageText)), totalPages);
    state.firewallRules.page = nextPage;
    renderFirewallRulesTable();
}

function renderMetricCards(id, metrics) {
    const container = document.getElementById(id);
    if (!container)
        return;

    container.replaceChildren();

    if (!metrics.length) {
        const card = document.createElement("div");
        card.className = "metric-card";
        const label = document.createElement("span");
        label.textContent = "Jail";
        const value = document.createElement("strong");
        value.textContent = "Keine Daten verfügbar";
        card.append(label, value);
        container.append(card);
        return;
    }

    metrics.forEach(metric => {
        const card = document.createElement("div");
        card.className = "metric-card";
        const label = document.createElement("span");
        label.textContent = metric.label;
        const value = document.createElement("strong");
        value.textContent = metric.value;
        card.append(label, value);
        container.append(card);
    });
}

function renderTokenRow(id, items, options = {}) {
    const container = document.getElementById(id);
    if (!container)
        return;

    container.replaceChildren();

    if (!items.length && options.emptyText) {
        const token = document.createElement("span");
        token.className = "pf-v6-c-label pf-m-outline token";
        token.textContent = options.emptyText;
        container.append(token);
        return;
    }

    items.forEach(item => {
        if (options.clickable) {
            const button = document.createElement("button");
            button.type = "button";
            button.className = "pf-v6-c-button pf-m-tertiary token-button";
            button.textContent = item;
            button.addEventListener("click", () => options.onClick(item));
            container.append(button);
            return;
        }

        const token = document.createElement("span");
        token.className = "pf-v6-c-label pf-m-outline token";
        token.textContent = item;
        container.append(token);
    });
}

function getSecurityLogSource(id = state.securityLogSource) {
    return SECURITY_LOG_SOURCES.find(source => source.id === id) || SECURITY_LOG_SOURCES[0];
}

function renderSecurityLogSourceOptions() {
    const menuList = document.getElementById("security-log-menu-list");
    const toggleText = document.getElementById("security-log-source-text");
    if (!menuList || !toggleText)
        return;

    const currentSource = getSecurityLogSource();
    toggleText.textContent = currentSource.label;

    menuList.replaceChildren();
    SECURITY_LOG_SOURCES.forEach(source => {
        const item = document.createElement("li");
        item.setAttribute("role", "menuitem");
        item.className = "pf-v6-c-menu__item";
        if (source.id === state.securityLogSource)
            item.classList.add("pf-m-selected");
        item.textContent = source.label;

        const button = document.createElement("button");
        button.type = "button";
        button.className = "pf-v6-c-menu__item";
        if (source.id === state.securityLogSource)
            button.classList.add("pf-m-selected");
        button.textContent = source.label;
        button.addEventListener("click", () => {
            switchSecurityLogSource(source.id);
            closeSecurityLogMenu();
        });

        const listItem = document.createElement("li");
        listItem.setAttribute("role", "none");
        listItem.append(button);
        menuList.append(listItem);
    });
}

function toggleSecurityLogMenu() {
    const menu = document.getElementById("security-log-menu");
    if (!menu)
        return;
    menu.hidden = !menu.hidden;
}

function closeSecurityLogMenu() {
    const menu = document.getElementById("security-log-menu");
    if (menu)
        menu.hidden = true;
}

function buildSecurityLogArgs(source = getSecurityLogSource()) {
    const args = ["journalctl", "-q", "--no-pager", "-n", String(SECURITY_LOG_FETCH_LIMIT), "-o", "json"];
    let hasMatch = false;

    source.units.forEach(unit => {
        if (hasMatch)
            args.push("+");
        args.push(`_SYSTEMD_UNIT=${unit}`);
        hasMatch = true;
    });

    if (source.kernelScope) {
        if (hasMatch)
            args.push("+");
        args.push("_TRANSPORT=kernel");
    }

    return args;
}

function getSecurityLogUrl(source = getSecurityLogSource()) {
    const params = new URLSearchParams({ prio: "debug" });
    if (source.units.length)
        params.set("_SYSTEMD_UNIT", source.units.join(","));
    if (source.kernelScope)
        params.set("_TRANSPORT", "kernel");

    return `/system/logs/#/?${params.toString()}`;
}

function getSecurityLogParentOptions(source = getSecurityLogSource()) {
    const options = { prio: "debug" };
    if (source.units.length)
        options._SYSTEMD_UNIT = source.units.join(",");
    if (source.kernelScope)
        options._TRANSPORT = "kernel";
    return options;
}

function isKernelJournalEntry(entry) {
    return entry._TRANSPORT === "kernel" || entry.SYSLOG_IDENTIFIER === "kernel" || entry._COMM === "kernel";
}

function isUfwKernelMessage(message) {
    return /\bUFW\b|\[UFW\s+/i.test(message);
}

function isFirewallKernelMessage(message) {
    const normalized = normalizeWhitespace(message);
    return isUfwKernelMessage(normalized) ||
        /\b(?:IN|OUT|MAC|SRC|DST|LEN|TOS|PREC|TTL|ID|PROTO|SPT|DPT|WINDOW|RES|UID|GID)=/i.test(normalized) ||
        /\b(?:iptables|ip6tables|nftables|netfilter)\b/i.test(normalized);
}

function entryMatchesSecurityLogSource(entry, source = getSecurityLogSource()) {
    if (source.units.includes(entry._SYSTEMD_UNIT))
        return true;

    if (!source.kernelScope || !isKernelJournalEntry(entry))
        return false;

    const message = getJournalMessage(entry);
    if (source.kernelScope === "ufw")
        return isUfwKernelMessage(message);
    if (source.kernelScope === "iptables")
        return isFirewallKernelMessage(message) && !isUfwKernelMessage(message);

    return isFirewallKernelMessage(message);
}

function formatJournalTimestamp(entry, options) {
    const timestamp = Number(entry.__REALTIME_TIMESTAMP);
    if (!Number.isFinite(timestamp))
        return "";

    return new Date(timestamp / 1000).toLocaleString("zh-CN", options);
}

function formatJournalDay(entry) {
    return formatJournalTimestamp(entry, {
        year: "numeric",
        month: "long",
        day: "numeric",
    });
}

function formatJournalTime(entry) {
    return formatJournalTimestamp(entry, {
        hour: "2-digit",
        minute: "2-digit",
    });
}

function getJournalIdentifier(entry) {
    return entry.SYSLOG_IDENTIFIER || entry._COMM || entry._SYSTEMD_UNIT || "journal";
}

function getJournalMessage(entry) {
    return String(entry.MESSAGE || "").trim() || "Keine Protokollmeldung vorhanden.";
}

function openJournalEntry(entry) {
    if (!entry.__CURSOR)
        return;

    const parentOptions = encodeURIComponent(JSON.stringify(getSecurityLogParentOptions()));
    cockpit.jump(`system/logs#/${entry.__CURSOR}?parent_options=${parentOptions}`);
}

function getSecurityLogContainer() {
    return document.getElementById("security-log-list");
}

function renderSecurityLogs(entries) {
    const container = getSecurityLogContainer();
    if (!container)
        return;

    container.replaceChildren();

    if (!entries.length) {
        const empty = document.createElement("div");
        empty.className = "empty-message";
        empty.textContent = "Keine Sicherheitsprotokolle vorhanden.";
        container.append(empty);
        return;
    }

    let currentDay = "";
    entries.forEach(entry => {
        const day = formatJournalDay(entry);
        if (day && day !== currentDay) {
            currentDay = day;
            const heading = document.createElement("div");
            heading.className = "panel-heading";
            heading.textContent = day;
            container.append(heading);
        }

        const row = document.createElement("div");
        row.className = "cockpit-logline";
        row.role = "row";
        row.tabIndex = 0;
        row.addEventListener("click", () => openJournalEntry(entry));
        row.addEventListener("keydown", event => {
            if (event.key === "Enter")
                openJournalEntry(entry);
        });

        const warning = document.createElement("div");
        warning.className = "cockpit-log-warning";
        warning.role = "cell";
        warning.textContent = Number(entry.PRIORITY) < 4 ? "!" : "";

        const time = document.createElement("div");
        time.className = "cockpit-log-time";
        time.role = "cell";
        time.textContent = formatJournalTime(entry);

        const message = document.createElement("span");
        message.className = "cockpit-log-message";
        message.role = "cell";
        message.textContent = getJournalMessage(entry);

        const service = document.createElement("div");
        service.className = "cockpit-log-service";
        service.role = "cell";
        service.textContent = getJournalIdentifier(entry);

        row.append(warning, time, message, service);
        container.append(row);
    });
}

function renderSecurityLogMessage(message) {
    const container = getSecurityLogContainer();
    if (!container)
        return;

    const empty = document.createElement("div");
    empty.className = "empty-message";
    empty.textContent = message;
    container.replaceChildren(empty);
}

async function refreshSecurityLogs() {
    if (state.refreshLocks.logs) {
        state.securityLogsRefreshPending = true;
        renderSecurityLogMessage("Sicherheitsprotokoll wird geladen...");
        return state.refreshLocks.logs;
    }

    const task = withRefreshLock("logs", async () => {
        if (state.superuserAllowed === null)
            return;

        const sourceId = state.securityLogSource;
        const source = getSecurityLogSource();
        renderSecurityLogMessage("Sicherheitsprotokoll wird geladen...");
        const result = await captureRead(buildSecurityLogArgs(source));
        if (state.securityLogSource !== sourceId) {
            state.securityLogsRefreshPending = true;
            return;
        }

        if (!result.ok) {
            renderSecurityLogMessage(isPermissionError(result.output)
                ? "Zum Lesen des Systemprotokolls sind Administratorrechte erforderlich."
                : summarizeOutput(result.output, false));
            return;
        }

        const entries = String(result.output || "")
            .split(/\r?\n/)
            .map(line => line.trim())
            .filter(Boolean)
            .map(line => {
                try {
                    return JSON.parse(line);
                } catch (_error) {
                    return null;
                }
            })
            .filter(Boolean)
            .filter(entry => entryMatchesSecurityLogSource(entry, source))
            .slice(-SECURITY_LOG_DISPLAY_LIMIT);

        renderSecurityLogs(entries);
    });

    return task.finally(() => {
        if (state.securityLogsRefreshPending && state.superuserAllowed !== null) {
            state.securityLogsRefreshPending = false;
            return refreshSecurityLogs();
        }
    });
}

function switchSecurityLogSource(sourceId) {
    state.securityLogSource = sourceId;
    renderSecurityLogSourceOptions();
    refreshSecurityLogs();
}

function positionSecurityLogMenu() {
    const toggle = document.getElementById("security-log-source-toggle");
    const menu = document.getElementById("security-log-menu");
    if (!toggle || !menu)
        return;
    const rect = toggle.getBoundingClientRect();
    menu.style.position = "fixed";
    menu.style.top = (rect.bottom + 4) + "px";
    menu.style.left = rect.left + "px";
    menu.style.minWidth = rect.width + "px";
}

function normalizeStatus(value) {
    const normalized = String(value || "").trim().toLowerCase();
    const mapping = {
        active: "Aktiv",
        inactive: "Inaktiv",
        running: "Aktiv",
        failed: "Fehlgeschlagen",
        enabled: "Aktiviert",
        disabled: "Deaktiviert",
        loaded: "Geladen",
        masked: "Maskiert",
    };
    return mapping[normalized] || value || "Unbekannt";
}

function normalizeWhitespace(value) {
    return String(value || "").replace(/\s+/g, " ").trim();
}

function parseSystemdShow(output) {
    const values = {};
    String(output || "").split(/\r?\n/).forEach(line => {
        const index = line.indexOf("=");
        if (index <= 0)
            return;

        values[line.slice(0, index)] = line.slice(index + 1).trim();
    });
    return values;
}

async function resolveServiceUnit(candidates, fallback) {
    for (const candidate of candidates) {
        const result = await captureRead(["systemctl", "show", candidate, "--property=LoadState", "--value"]);
        if (result.ok && String(result.output || "").trim() !== "not-found")
            return candidate;
    }

    return fallback;
}

async function resolveFail2BanService() {
    state.fail2banService = await resolveServiceUnit(FAIL2BAN_SERVICE_CANDIDATES, "fail2ban.service");
    return state.fail2banService;
}

// ---------------------------------------------------------------------------
// Firewall backends
//
// A backend is one entry in FIREWALL_BACKENDS. It owns exactly four things:
//
//   capabilities          which buttons the UI may offer (enable, disable,
//                         reload, addRule, deleteRule, persist)
//   read()                turns manager specific output into the common status
//                         shape { summary, statusLabel, tone, details, columns,
//                         rows, chains, persist, emptyText }
//   buildAddRule()/...    turns form values or a table row into command steps
//   quickActions()        backend specific one-shot commands ("reload", "save")
//
// The UI layer below never mentions ufw/iptables/nft/firewalld by name; it only
// talks to the selected backend. A new manager therefore only needs a new
// object here.
// ---------------------------------------------------------------------------

const FIREWALL_BACKEND_ORDER = ["firewalld", "ufw", "nftables", "iptables"];
const FIREWALL_BACKEND_STORAGE_KEY = "cockpit-security:firewall-backend";

const FIREWALL_CONTEXT = {
    read: captureRead,
    tool: getToolCommand,
};

function getFirewallBackend(id = state.firewallBackend) {
    return FIREWALL_BACKENDS[id] || FIREWALL_BACKENDS.ufw;
}

async function permissionResult(label, output, units = []) {
    const details = [["Berechtigung", "Zum Lesen der Regeln sind Administratorrechte erforderlich."]];
    for (const unit of units) {
        const result = await captureRead(["systemctl", "show", unit, "--property=ActiveState,UnitFileState,LoadState"]);
        if (!result.ok)
            continue;
        const values = parseSystemdShow(result.output);
        if (!values.LoadState || values.LoadState === "not-found")
            continue;
        details.push([unit, `${normalizeStatus(values.ActiveState || "")} / ${normalizeStatus(values.UnitFileState || "")}`]);
    }

    return {
        kind: "permission",
        summary: `${label}-Regeln können nur mit Administratorrechten gelesen werden.`,
        detail: summarizeOutput(output, false),
        details,
    };
}

function backendError(output) {
    return { kind: "error", message: output };
}

function persistDetail(persist) {
    if (!persist)
        return ["Dauerhafte Speicherung", "Unbekannt"];

    const stateLabels = {
        saved: "Dauerhaft gespeichert",
        managed: "Vom Dienst verwaltet",
        pending: "Laufzeitregeln nicht gespeichert",
        missing: "Keine Datei zur dauerhaften Speicherung gefunden",
        unreadable: "Nicht lesbar (Administratorrechte erforderlich)",
        unsupported: "Keine dauerhafte Speicherung erkannt",
        unknown: "Nicht feststellbar",
    };
    const where = persist.file ? ` (${persist.file})` : "";
    return ["Dauerhafte Speicherung", `${stateLabels[persist.state] || stateLabels.unknown}${where}`];
}

function buildPersistSteps(mechanism, file) {
    if (mechanism === "netfilter-persistent")
        return [{ args: ["netfilter-persistent", "save"], label: "iptables-Regeln speichern" }];

    const target = file || "/etc/iptables/rules.v4";
    return [{
        args: ["sh", "-c", `umask 077 && iptables-save > '${target}'`],
        label: `iptables-Regeln speichern nach ${target}`,
    }];
}

function buildNftablesPersistSteps(file) {
    const target = file || "/etc/nftables.conf";
    return [{
        args: ["sh", "-c", `umask 077 && nft list ruleset > '${target}' && systemctl enable nftables.service`],
        label: `nftables-Regeln speichern nach ${target}`,
    }];
}

const FIREWALL_BACKENDS = {
    ufw: {
        id: "ufw",
        label: "UFW",
        toolId: "ufw",
        addRuleLabel: "Regel hinzufügen",
        dialogTitle: "UFW-Regel hinzufügen",
        dialogHint: "",
        fields: ["action", "port", "protocol", "source"],
        actionOptions: [
            { value: "allow", label: "Erlauben (allow)" },
            { value: "deny", label: "Blockieren (deny)" },
            { value: "reject", label: "Zurückweisen (reject)" },
        ],
        capabilities: ["enable", "disable", "reload", "addRule", "deleteRule"],
        async read(ctx) {
            const ufw = ctx.tool("ufw");
            const [verbose, numbered] = await Promise.all([
                ctx.read([ufw, "status", "verbose"]),
                ctx.read([ufw, "status", "numbered"]),
            ]);

            if (!verbose.ok && !numbered.ok) {
                if (isPermissionError(numbered.output) || isPermissionError(verbose.output))
                    return permissionResult("UFW", numbered.output || verbose.output, ["ufw.service"]);
                return backendError(numbered.output || verbose.output);
            }

            return parseUfwStatus(numbered.output, verbose.output);
        },
        buildAddRule(ctx, values) {
            const ufw = ctx.tool("ufw");
            const args = values.source
                ? [ufw, values.action, "from", values.source, "to", "any", "port", values.port, "proto", values.protocol]
                : [ufw, values.action, `${values.port}/${values.protocol}`];
            return { steps: [{ args, label: `UFW ${values.action} ${values.port}/${values.protocol}` }] };
        },
        buildDeleteRule(ctx, rule) {
            return {
                steps: [{
                    args: [ctx.tool("ufw"), "--force", "delete", rule.value],
                    label: `UFW Regel löschen #${rule.value}`,
                }],
            };
        },
        quickActions(ctx) {
            const ufw = ctx.tool("ufw");
            return {
                enable: {
                    args: [ufw, "--force", "enable"],
                    label: "UFW aktivieren",
                    confirm: "Nach dem Aktivieren gelten die aktuellen Regeln sofort. Prüfe vorher, ob die Ports für deinen Verwaltungszugang freigegeben sind, damit die Verbindung erhalten bleibt.",
                },
                disable: {
                    args: [ufw, "disable"],
                    label: "UFW deaktivieren",
                    confirm: "Beim Deaktivieren entfällt die gesamte eingehende Filterung sofort. Eingehender Verkehr wird dann nicht mehr blockiert.",
                    danger: true,
                },
                reload: { args: [ufw, "reload"], label: "UFW neu laden" },
            };
        },
    },

    iptables: {
        id: "iptables",
        label: "iptables",
        toolId: "iptables",
        addRuleLabel: "Regel einfügen",
        dialogTitle: "iptables-Regel einfügen",
        dialogHint: "Die Regel wird am Anfang der ausgewählten Kette eingefügt und gilt sofort. Für die Übernahme nach einem Neustart bitte „Regeln speichern“ verwenden.",
        fields: ["chain", "action", "port", "protocol", "source"],
        actionOptions: [
            { value: "ACCEPT", label: "Erlauben (ACCEPT)" },
            { value: "DROP", label: "Verwerfen (DROP)" },
            { value: "REJECT", label: "Zurückweisen (REJECT)" },
        ],
        capabilities: ["addRule", "deleteRule", "persist"],
        fallbackChains: ["INPUT", "FORWARD", "OUTPUT"],
        async read(ctx) {
            const tool = ctx.tool("iptables");
            const [rules, persist, manager] = await Promise.all([
                ctx.read([tool, "-S"]),
                readIptablesPersistence(ctx),
                detectIptablesManager(ctx),
            ]);

            if (!rules.ok) {
                if (isPermissionError(rules.output)) {
                    const permission = await permissionResult("iptables", rules.output, ["iptables.service", "netfilter-persistent.service"]);
                    permission.persist = persist;
                    return permission;
                }
                return backendError(rules.output);
            }

            const parsed = parseIptablesRuleset(rules.output, persist);
            if (manager) {
                // UFW and firewalld generate these very rules. Warn, don't block:
                // the operator is allowed to touch them, same as on the CLI.
                parsed.manager = manager;
                parsed.notices = [
                    `${manager} verwaltet die Firewall dieses Rechners und erzeugt diese Regeln. Änderungen können beim Neuladen überschrieben werden.`,
                    ...parsed.notices,
                ];
                parsed.persist = {
                    ...persist,
                    manager,
                };
            }
            return parsed;
        },
        buildAddRule(ctx, values) {
            const args = [ctx.tool("iptables"), "-I", values.chain, "-p", values.protocol];
            if (values.source)
                args.push("-s", values.source);
            args.push("--dport", values.port, "-j", values.action);
            return { steps: [{ args, label: `iptables Regel einfügen in ${values.chain}` }] };
        },
        buildDeleteRule(ctx, rule) {
            return {
                steps: [{
                    args: [ctx.tool("iptables"), "-D", rule.chain, ...rule.tokens],
                    label: `iptables-Regel aus ${rule.chain} löschen`,
                }],
            };
        },
        quickActions() {
            const persist = state.firewallPersist || {};
            const managerWarning = persist.manager
                ? `\n\nHinweis: Die Regeln werden durch ${persist.manager} erzeugt und dauerhaft gespeichert. Hier gespeicherte Regeln können damit in Konflikt stehen.`
                : "";
            return {
                persist: {
                    steps: buildPersistSteps(persist.mechanism, persist.file),
                    confirm: `Die aktuellen Laufzeitregeln dauerhaft speichern, damit sie nach einem Neustart weiterhin gelten.${managerWarning}`,
                },
            };
        },
    },

    nftables: {
        id: "nftables",
        label: "nftables",
        toolId: "nftables",
        addRuleLabel: "Regel hinzufügen",
        dialogTitle: "nftables-Regel hinzufügen",
        dialogHint: "Die Regel wird am Ende der ausgewählten Kette angehängt und gilt sofort. Für die Übernahme nach einem Neustart bitte „Regeln speichern“ verwenden.",
        fields: ["chain", "action", "port", "protocol", "source"],
        actionOptions: [
            { value: "accept", label: "Erlauben (accept)" },
            { value: "drop", label: "Verwerfen (drop)" },
            { value: "reject", label: "Zurückweisen (reject)" },
        ],
        capabilities: ["addRule", "deleteRule", "persist"],
        async read(ctx) {
            const tool = ctx.tool("nftables");
            const [ruleset, persist] = await Promise.all([
                ctx.read([tool, "-a", "list", "ruleset"]),
                readNftablesPersistence(ctx),
            ]);

            if (!ruleset.ok) {
                if (isPermissionError(ruleset.output))
                    return permissionResult("nftables", ruleset.output, ["nftables.service"]);
                return backendError(ruleset.output);
            }

            return parseNftablesRuleset(ruleset.output, persist);
        },
        buildAddRule(ctx, values) {
            const chain = getNftablesChain(values.chain);
            if (!chain)
                return null;

            const args = [ctx.tool("nftables"), "add", "rule", chain.family, chain.table, chain.name];
            if (values.source)
                args.push(values.source.includes(":") ? "ip6" : "ip", "saddr", values.source);
            args.push(values.protocol, "dport", values.port, values.action);
            return { steps: [{ args, label: `nftables-Regel zu Kette ${chain.name} hinzufügen` }] };
        },
        buildDeleteRule(ctx, rule) {
            return {
                steps: [{
                    args: [ctx.tool("nftables"), "delete", "rule", rule.family, rule.table, rule.chain, "handle", String(rule.handle)],
                    label: `nftables-Regel aus ${rule.chain} löschen (Handle ${rule.handle})`,
                }],
            };
        },
        quickActions() {
            const persist = state.firewallPersist || {};
            return {
                persist: {
                    steps: buildNftablesPersistSteps(persist.file),
                    confirm: "Die aktuellen Regeln dauerhaft speichern und nftables.service für den Systemstart aktivieren.",
                },
            };
        },
    },

    firewalld: {
        id: "firewalld",
        label: "firewalld",
        toolId: "firewalld",
        addRuleLabel: "Port hinzufügen",
        dialogTitle: "firewalld-Port hinzufügen",
        dialogHint: "Schreibt in die Laufzeit- und dauerhafte Konfiguration der Standardzone. Mit Quell-IP werden accept/drop-Rich-Rules erzeugt. Ohne Quell-IP wird der Port immer freigegeben, auch bei Auswahl von drop. Prioritäten sind hier nicht einstellbar.",
        fields: ["action", "port", "protocol", "source"],
        actionOptions: [
            { value: "accept", label: "Erlauben (accept)" },
            { value: "drop", label: "Verwerfen (drop)" },
        ],
        capabilities: ["reload", "addRule", "deleteRule"],
        async read(ctx) {
            const tool = ctx.tool("firewalld");
            const [stateResult, zoneResult, runtime, permanent] = await Promise.all([
                ctx.read([tool, "--state"]),
                ctx.read([tool, "--get-default-zone"]),
                ctx.read([tool, "--list-all"]),
                ctx.read([tool, "--list-all", "--permanent"]),
            ]);

            if (!runtime.ok && !permanent.ok) {
                if (isPermissionError(runtime.output) || isPermissionError(permanent.output))
                    return permissionResult("firewalld", runtime.output || permanent.output, ["firewalld.service"]);
                return backendError(runtime.output || permanent.output);
            }

            return parseFirewalldStatus({ stateResult, zoneResult, runtime, permanent });
        },
        buildAddRule(ctx, values) {
            const tool = ctx.tool("firewalld");
            const steps = [];
            if (values.source) {
                const family = values.source.includes(":") ? "ipv6" : "ipv4";
                const action = values.action === "drop" ? "drop" : "accept";
                const rule = `rule family="${family}" source address="${values.source}" port port="${values.port}" protocol="${values.protocol}" ${action}`;
                steps.push({ args: [tool, `--add-rich-rule=${rule}`], label: `firewalld Rich Rule hinzufügen (${values.port}/${values.protocol})` });
                steps.push({ args: [tool, "--permanent", `--add-rich-rule=${rule}`], label: "firewalld Dauerhafte Konfiguration schreiben" });
            } else {
                steps.push({ args: [tool, `--add-port=${values.port}/${values.protocol}`], label: `firewalld Port freigeben ${values.port}/${values.protocol}` });
                steps.push({ args: [tool, "--permanent", `--add-port=${values.port}/${values.protocol}`], label: "firewalld Dauerhafte Konfiguration schreiben" });
            }
            return { steps };
        },
        buildDeleteRule(ctx, rule) {
            const tool = ctx.tool("firewalld");
            const steps = [];
            const flag = `--remove-${rule.type === "rich" ? "rich-rule" : rule.type}`;
            if (rule.inRuntime !== false)
                steps.push({ args: [tool, `${flag}=${rule.value}`], label: `firewalld Laufzeiteintrag löschen: ${rule.value}` });
            if (rule.inPermanent)
                steps.push({ args: [tool, "--permanent", `${flag}=${rule.value}`], label: `firewalld Dauerhaften Eintrag löschen: ${rule.value}` });
            return { steps };
        },
        quickActions(ctx) {
            return {
                reload: { args: [ctx.tool("firewalld"), "--reload"], label: "firewalld neu laden" },
            };
        },
    },
};

function parseUfwStatus(numberedOutput, verboseOutput) {
    const rules = [];
    String(numberedOutput || "").split(/\r?\n/).forEach(line => {
        const match = line.match(/^\[\s*(\d+)\]\s+(.+?)\s{2,}(\S+)\s+(\S+)\s+(.+)$/);
        if (!match)
            return;

        rules.push({
            number: match[1],
            to: match[2].trim(),
            action: match[3],
            direction: match[4],
            from: match[5].trim(),
        });
    });

    const sourceText = verboseOutput || numberedOutput;
    const status = sourceText.match(/Status:\s*(.+)/i)?.[1]?.trim() || "unknown";
    const defaults = sourceText.match(/Default:\s*(.+)/i)?.[1]?.trim() || "";
    const logging = sourceText.match(/Logging:\s*(.+)/i)?.[1]?.trim() || "";
    const isActive = status.toLowerCase() === "active";

    return {
        summary: isActive
            ? `UFW ist aktiv. Erkannte Regeln: ${rules.length}.`
            : "UFW ist derzeit deaktiviert.",
        statusLabel: isActive ? "Aktiv" : normalizeStatus(status),
        tone: isActive ? "success" : "warning",
        ruleCount: String(rules.length),
        policySummary: defaults ? `Standardrichtlinie: ${defaults}` : "Keine Standardrichtlinie erkannt.",
        details: [
            ["Status", normalizeStatus(status)],
            defaults ? ["Standardrichtlinie", defaults] : null,
            logging ? ["Protokoll", logging] : null,
            ["Regelanzahl", String(rules.length)],
        ].filter(Boolean),
        columns: ["Nummer", "Ziel", "Aktion", "Richtung", "Quelle"],
        rows: rules.map(rule => ({
            cells: [rule.number, rule.to, rule.action, rule.direction, rule.from],
            delete: {
                kind: "ufw",
                value: rule.number,
                label: "Löschen",
            },
        })),
        emptyText: isActive ? "Derzeit keine UFW-Regeln." : "UFW ist deaktiviert. Keine Regeln anzuzeigen.",
        chains: [],
        persist: { state: "managed", mechanism: "ufw", file: "/etc/ufw" },
    };
}

function describeIptablesRule(tokens) {
    const description = { target: "", protocol: "", source: "", destination: "", ports: "", spec: tokens.join(" ") };

    for (let index = 0; index < tokens.length; index++) {
        const token = tokens[index];
        const next = tokens[index + 1];
        switch (token) {
        case "-j":
        case "-g":
        case "--jump":
        case "--goto":
            description.target = next || "";
            index++;
            break;
        case "-p":
        case "--protocol":
            description.protocol = next || "";
            index++;
            break;
        case "-s":
        case "--source":
            description.source = next || "";
            index++;
            break;
        case "-d":
        case "--destination":
            description.destination = next || "";
            index++;
            break;
        case "--dport":
        case "--destination-port":
            description.ports = next || "";
            index++;
            break;
        default:
            break;
        }
    }

    return description;
}

function splitIptablesSpec(spec) {
    // `iptables -S` quotes arguments such as comments; split without losing the
    // quoted value so `-D <chain> <spec>` can be replayed verbatim.
    const tokens = [];
    const pattern = /"([^"]*)"|'([^']*)'|(\S+)/g;
    let match;
    while ((match = pattern.exec(spec)) !== null) {
        if (match[1] !== undefined)
            tokens.push(match[1]);
        else if (match[2] !== undefined)
            tokens.push(match[2]);
        else
            tokens.push(match[3]);
    }
    return tokens;
}

function parseIptablesRuleset(output, persist) {
    const policies = {};
    const chains = [];
    const rules = [];

    String(output || "").split(/\r?\n/).forEach(line => {
        const trimmed = line.trim();
        if (!trimmed)
            return;

        const policyMatch = trimmed.match(/^-P\s+(\S+)\s+(\S+)$/);
        if (policyMatch) {
            policies[policyMatch[1]] = policyMatch[2];
            if (!chains.includes(policyMatch[1]))
                chains.push(policyMatch[1]);
            return;
        }

        const chainMatch = trimmed.match(/^-N\s+(\S+)$/);
        if (chainMatch) {
            if (!chains.includes(chainMatch[1]))
                chains.push(chainMatch[1]);
            return;
        }

        const ruleMatch = trimmed.match(/^-A\s+(\S+)\s+(.*)$/);
        if (!ruleMatch)
            return;

        const tokens = splitIptablesSpec(ruleMatch[2].trim());
        if (!tokens.length)
            return;
        if (!chains.includes(ruleMatch[1]))
            chains.push(ruleMatch[1]);
        rules.push({ chain: ruleMatch[1], tokens, ...describeIptablesRule(tokens) });
    });

    const inputPolicy = policies.INPUT || "Nicht definiert";
    const policySummary = Object.keys(policies).length
        ? Object.entries(policies).map(([chain, policy]) => `${chain}=${policy}`).join(", ")
        : "Keine Standardrichtlinie erkannt.";
    const unpersisted = persist?.state === "pending" || persist?.state === "missing";
    const inputFiltered = inputPolicy === "DROP" || inputPolicy === "REJECT" || rules.some(rule => rule.chain === "INPUT");
    const dockerChains = chains.filter(chain => chain.startsWith("DOCKER"));
    const notices = [];

    if (!rules.some(rule => rule.chain === "INPUT"))
        notices.push("INPUT-Kette enthält keine Regeln. Der gesamte eingehende Verkehr ist erlaubt.");
    if (dockerChains.length)
        notices.push(`Erkannt: Docker -Kette (${dockerChains.join(", ")}), Diese Regeln werden durch Docker verwaltet und nach einem Neustart wiederhergestellt durch Docker selbst.`);
    if (unpersisted && persist?.boot !== "enabled")
        notices.push("Kein Laden beim Systemstart erkannt (netfilter-persistent / iptables.service), Gespeicherte Regeln werden nach einem Neustart nicht wirksam.");

    return {
        summary: [
            `INPUT-Kettenrichtlinie: ${inputPolicy}, insgesamt ${rules.length} Regeln.`,
            !inputFiltered ? "Der Rechner filtert derzeit keinen eingehenden Verkehr." : "",
            unpersisted && persist?.boot === "enabled" ? "Laufzeitregeln sind noch nicht gespeichert." : "",
        ].filter(Boolean).join(""),
        statusLabel: inputPolicy === "ACCEPT" && !inputFiltered ? "Eingehender Verkehr ungefiltert" : `Richtlinie ${inputPolicy}`,
        tone: inputPolicy === "ACCEPT" && !inputFiltered ? "warning" : "success",
        ruleCount: String(rules.length),
        policySummary: `Standardrichtlinie: ${policySummary}`,
        notices,
        details: [
            ["Standardrichtlinie", policySummary],
            ["Regelanzahl", String(rules.length)],
            ["Kette", chains.join(", ") || "Keine"],
            dockerChains.length ? ["Docker-Ketten", dockerChains.join(", ")] : null,
            persistDetail(persist),
        ].filter(Boolean),
        columns: ["Kette", "Ziel", "Protokoll", "Quelle", "Port", "Regel"],
        rows: rules.map(rule => ({
            cells: [
                rule.chain,
                rule.target || "-",
                rule.protocol || "any",
                rule.source || "any",
                rule.ports || "-",
                rule.spec,
            ],
            delete: {
                kind: "iptables",
                chain: rule.chain,
                tokens: rule.tokens,
                value: rule.spec,
                description: `iptables-Regel in Kette ${rule.chain}`,
                label: "Löschen",
                disabled: rule.chain.startsWith("DOCKER"),
            },
        })),
        emptyText: "Derzeit keine iptables-Regeln.",
        chains: chains.map(chain => ({
            value: chain,
            label: chain.startsWith("DOCKER") ? `${chain} (Docker verwaltet)` : chain,
        })),
        persist,
    };
}

// Which higher level tool owns the rules currently in the kernel. ufw and
// firewalld both generate iptables/nftables rules; editing them from here works
// until that tool reloads.
async function detectIptablesManager(ctx) {
    const script = [
        "if systemctl is-active --quiet firewalld 2>/dev/null; then echo firewalld; exit 0; fi",
        "if systemctl is-active --quiet ufw 2>/dev/null; then echo ufw; exit 0; fi",
        "if [ -f /etc/ufw/ufw.conf ] && grep -q '^ENABLED=yes' /etc/ufw/ufw.conf 2>/dev/null; then echo ufw; exit 0; fi",
        "exit 0",
    ].join("\n");

    const result = await ctx.read(["sh", "-c", script]);
    if (!result.ok)
        return "";

    return String(result.output || "").trim().split(/\s+/).filter(Boolean)[0] || "";
}

async function readIptablesPersistence(ctx) {
    const script = [
        "mech=iptables-save",
        "file=/etc/iptables/rules.v4",
        "if command -v netfilter-persistent >/dev/null 2>&1; then mech=netfilter-persistent; fi",
        "if [ -e /etc/sysconfig/iptables ]; then file=/etc/sysconfig/iptables; fi",
        "printf 'MECHANISM=%s\\n' \"$mech\"",
        "printf 'FILE=%s\\n' \"$file\"",
        "if ! command -v iptables-save >/dev/null 2>&1; then printf 'SAVE=unsupported\\n';",
        "elif [ ! -e \"$file\" ]; then printf 'SAVE=missing\\n';",
        "elif [ ! -r \"$file\" ]; then printf 'SAVE=unreadable\\n';",
        "else",
        "  current=$(iptables-save 2>/dev/null | grep -v '^#' | grep -v '^[[:space:]]*$')",
        "  saved=$(grep -v '^#' \"$file\" 2>/dev/null | grep -v '^[[:space:]]*$')",
        "  if [ -z \"$current\" ]; then printf 'SAVE=unknown\\n';",
        "  elif [ \"$current\" = \"$saved\" ]; then printf 'SAVE=saved\\n';",
        "  else printf 'SAVE=pending\\n'; fi",
        "fi",
        "if systemctl is-enabled netfilter-persistent.service >/dev/null 2>&1; then printf 'BOOT=enabled\\n';",
        "elif systemctl is-enabled iptables.service >/dev/null 2>&1; then printf 'BOOT=enabled\\n';",
        "else printf 'BOOT=disabled\\n'; fi",
        "if iptables -S 2>/dev/null | grep -qE '^-N DOCKER'; then printf 'FOREIGN=docker\\n'; else printf 'FOREIGN=none\\n'; fi",
    ].join("\n");

    const result = await ctx.read(["sh", "-c", script]);
    return parsePersistenceReport(result.ok ? result.output : "", { mechanism: "iptables-save", file: "/etc/iptables/rules.v4" });
}

function parsePersistenceReport(output, defaults = {}) {
    const values = {};
    String(output || "").split(/\r?\n/).forEach(line => {
        const index = line.indexOf("=");
        if (index > 0)
            values[line.slice(0, index).trim()] = line.slice(index + 1).trim();
    });

    const known = ["saved", "pending", "missing", "unreadable", "unsupported", "unknown"];
    const boot = values.BOOT || "";
    const foreign = values.FOREIGN && values.FOREIGN !== "none" ? values.FOREIGN : "";
    return {
        mechanism: values.MECHANISM || defaults.mechanism || "",
        file: values.FILE || defaults.file || "",
        boot,
        foreign,
        // A rules file only protects against reboots if something loads it at
        // boot; without that the file is decoration.
        loadedAtBoot: boot === "enabled",
        // `flush ruleset` in the nftables config wipes everything, including
        // tables owned by iptables or Docker, when the service starts.
        flushesEverything: values.FLUSH === "ruleset",
        declaredTables: String(values.TABLES || "").split(",").map(item => item.trim()).filter(Boolean),
        state: known.includes(values.SAVE) ? values.SAVE : "unknown",
    };
}

function getNftablesChain(value) {
    const match = String(value || "").match(/^(\S+)\s+(\S+)\/(\S+)$/);
    return match ? { family: match[1], table: match[2], name: match[3] } : null;
}

function parseNftablesRuleset(output, persist) {
    const chains = [];
    const rules = [];
    const stack = [];
    const foreignTables = new Map();

    String(output || "").split(/\r?\n/).forEach(line => {
        const trimmed = line.trim();
        if (!trimmed)
            return;

        // `nft list ruleset` also prints iptables-nft managed tables and warns
        // about them. Such tables belong to iptables (or Docker) and must not be
        // edited or saved through nftables.
        const foreignMatch = trimmed.match(/^#\s*Warning: table\s+(\S+)\s+(\S+)\s+is managed by\s+([^,\s]+)/i);
        if (foreignMatch) {
            foreignTables.set(`${foreignMatch[1]} ${foreignMatch[2]}`, foreignMatch[3]);
            return;
        }

        if (trimmed.startsWith("#"))
            return;

        const current = stack[stack.length - 1];
        if (current?.type === "chain") {
            const handleMatch = trimmed.match(/^(.*?)#\s*handle\s+(\d+)\s*$/);
            if (handleMatch) {
                rules.push({
                    family: current.family,
                    table: current.table,
                    chain: current.name,
                    handle: handleMatch[2],
                    spec: handleMatch[1].trim().replace(/;$/, ""),
                });
                return;
            }

            const typeMatch = trimmed.match(/\btype\s+(\S+)\s/);
            const policyMatch = trimmed.match(/policy\s+([a-z-]+)/i);
            const hookMatch = trimmed.match(/hook\s+(\S+?)\s/);
            if (typeMatch)
                current.kind = typeMatch[1];
            if (policyMatch)
                current.policy = policyMatch[1];
            if (hookMatch)
                current.hook = hookMatch[1];
        }

        const opensBlock = trimmed.includes("{");
        const closesBlock = trimmed.includes("}");

        if (opensBlock && !closesBlock) {
            const tableMatch = trimmed.match(/^table\s+(\S+)\s+(\S+)/);
            const chainMatch = trimmed.match(/^chain\s+(\S+)/);
            if (tableMatch) {
                stack.push({ type: "table", family: tableMatch[1], table: tableMatch[2] });
            } else if (chainMatch) {
                const table = [...stack].reverse().find(entry => entry.type === "table");
                if (!table) {
                    stack.push({ type: "other" });
                    return;
                }
                const foreign = foreignTables.get(`${table.family} ${table.table}`) || "";
                const chain = {
                    type: "chain",
                    family: table.family,
                    table: table.table,
                    name: chainMatch[1],
                    policy: "",
                    hook: "",
                    kind: "filter",
                    foreign,
                    docker: /^DOCKER/i.test(chainMatch[1]),
                };
                stack.push(chain);
                chains.push(chain);
            } else {
                stack.push({ type: "other" });
            }
            return;
        }

        if (closesBlock && !opensBlock)
            stack.pop();
    });

    // Chains the UI may add rules to. Two conditions, both conservative:
    // the table must not belong to another tool (iptables-nft, Docker), and the
    // host must actually run its firewall through nftables.service. On hosts
    // where nftables.service is disabled (Debian/Ubuntu with iptables-nft and
    // Docker) the live ruleset belongs to iptables, and writing through nft
    // would silently edit another tool's state.
    const serviceManaged = persist?.loadedAtBoot === true;
    const declaredTables = persist?.declaredTables || [];
    const isDeclared = chain => declaredTables.includes(`${chain.family} ${chain.table}`);
    // A host running nftables.service owns exactly the tables its configuration
    // declares; everything else in the live ruleset was created by another tool.
    const editableChains = serviceManaged
        ? chains.filter(chain => isDeclared(chain) && !chain.foreign && !chain.docker)
        : [];
    const hookChains = chains.filter(chain => chain.hook);
    const policySummary = summarizeNftablesPolicies(hookChains);
    const unpersisted = persist?.state === "pending" || persist?.state === "missing";
    const inputChains = hookChains.filter(chain => chain.hook === "input");
    const inputFiltered = inputChains.length > 0 && inputChains.every(chain => chain.policy === "drop");
    const dockerChains = chains.filter(chain => chain.docker && !chain.foreign).map(chain => `${chain.family} ${chain.table}/${chain.name}`);
    const foreignNames = [...foreignTables.keys()];
    const readOnly = editableChains.length === 0;
    const orderedChains = [...editableChains].sort((left, right) => chainSortKey(left) - chainSortKey(right));

    const notices = [];
    if (inputChains.length === 0)
        notices.push("Keine Kette mit input-Hook gefunden. Auf nftables-Ebene ist keine Eingangsfilterung eingerichtet.");
    else if (!inputFiltered)
        notices.push(`Die input-Kette hat die Standardrichtlinie ${inputChains.map(chain => chain.policy || "Keine").join(", ")}, Eingehender Verkehr ist standardmäßig erlaubt.`);
    if (foreignNames.length)
        notices.push(`${foreignNames.join(", ")} durch ${foreignTables.values().next().value} verwaltet (normalerweise Docker), nicht mit nftables ändern oder speichern.`);
    if (!serviceManaged)
        notices.push("nftables.service ist nicht aktiviert und lädt die lokale Firewall nicht. Verwende zum Ändern das iptables-Backend oder aktiviere zuerst nftables.service.");
    else if (chains.some(chain => !chain.foreign && !isDeclared(chain)))
        notices.push(`Nicht in ${persist.file || "nftables Konfiguration"} deklarierte Tabellen (${[...new Set(chains.filter(chain => !chain.foreign && !isDeclared(chain)).map(chain => `${chain.family} ${chain.table}`))].join(", ")})können hier nicht geändert werden.`);
    if (persist?.flushesEverything && (foreignNames.length || chains.length))
        notices.push(`${persist.file || "nftables Konfiguration"} enthält “flush ruleset”, Starten nftables.service löscht alle aktuellen Regeln (einschließlich iptables/Docker -Regeln).`);
    if (dockerChains.length)
        notices.push(`Docker-Ketten (${dockerChains.join(", ")}) werden von Docker verwaltet und können hier nicht geändert werden.`);
    if (unpersisted && (foreignNames.length || !serviceManaged))
        notices.push("Die gespeicherte nftables-Konfiguration wird beim Neustart nicht geladen. iptables/Docker stellen ihre Regeln selbst wieder her.");

    return {
        summary: readOnly
            ? `Erkannt: ${rules.length} Regeln; alle gehören zu extern verwalteten Tabellen${foreignNames.length ? ` (${foreignNames.join(", ")})` : ""}.`
            : `Erkannte nftables-Regeln: ${rules.length}${unpersisted ? "; Laufzeitregeln noch nicht gespeichert" : ""}.`,
        statusLabel: inputChains.length ? describeNftablesPolicy(inputChains[0].policy) : "Keine Eingangsfilterung",
        tone: inputFiltered && !readOnly ? "success" : "warning",
        ruleCount: String(rules.length),
        policySummary: `Standardrichtlinie: ${policySummary}`,
        details: [
            ["Regelanzahl", String(rules.length)],
            ["Kette", chains.map(chain => `${chain.family} ${chain.table}/${chain.name}${chain.hook ? ` (${chain.hook})` : ""}${chain.foreign ? "[Extern verwaltet]" : ""}`).join(", ") || "Keine"],
            ["Standardrichtlinie", policySummary],
            foreignNames.length ? ["Extern verwaltete Tabellen", foreignNames.join(", ")] : null,
            persistDetail(persist),
        ].filter(Boolean),
        notices,
        readOnly,
        columns: ["Kette", "Regel", "Handle"],
        rows: rules.map(rule => ({
            cells: [`${rule.family} ${rule.table}/${rule.chain}`, rule.spec, rule.handle],
            delete: {
                kind: "nftables",
                family: rule.family,
                table: rule.table,
                chain: rule.chain,
                handle: rule.handle,
                value: rule.handle,
                description: `nftables-Regel in ${rule.chain} (Handle ${rule.handle})`,
                label: "Löschen",
                disabled: chains.some(chain => chain.name === rule.chain && chain.foreign),
            },
        })),
        emptyText: "Derzeit keine nftables-Regeln.",
        chains: orderedChains.map(chain => ({
            value: `${chain.family} ${chain.table}/${chain.name}`,
            label: `${chain.family} ${chain.table}/${chain.name}${chain.hook ? ` (hook ${chain.hook})` : ""}`,
        })),
        persist: foreignNames.length ? { ...(persist || {}), blocked: true, blockedReason: `${foreignNames.join(", ")} wird extern verwaltet. Speichern würde fremde Regeln in die nftables-Konfiguration übernehmen.` } : persist,
    };
}

function describeNftablesPolicy(policy) {
    if (policy === "drop")
        return "input standardmäßig blockiert";
    if (policy === "accept")
        return "input standardmäßig erlaubt";
    return policy ? `input ${policy}` : "input ohne Richtlinie";
}

function summarizeNftablesPolicies(hookChains) {
    const filterChains = hookChains.filter(chain => chain.kind === "filter" && ["input", "forward", "output"].includes(chain.hook));
    const groups = new Map();
    filterChains.forEach(chain => {
        const key = `${chain.family} ${chain.table}`;
        if (!groups.has(key))
            groups.set(key, []);
        groups.get(key).push(`${chain.hook}=${chain.policy || "Keine"}`);
    });

    if (!groups.size)
        return "Keine Hook-Richtlinie für ip/ip6-Filterketten erkannt.";

    return [...groups.entries()].map(([table, policies]) => `${table} ${policies.join("/")}`).join("; ");
}

function chainSortKey(chain) {
    if (chain.kind === "filter" && chain.hook === "input")
        return 0;
    if (chain.kind === "filter" && chain.hook)
        return 1;
    if (chain.hook)
        return 2;
    return 3;
}

async function readNftablesPersistence(ctx) {
    const script = [
        "file=/etc/nftables.conf",
        "printf 'MECHANISM=%s\\n' nftables.service",
        "printf 'FILE=%s\\n' \"$file\"",
        "if ! command -v nft >/dev/null 2>&1; then printf 'SAVE=unsupported\\n';",
        "elif ! systemctl cat nftables.service >/dev/null 2>&1; then printf 'SAVE=unsupported\\n';",
        "elif [ ! -e \"$file\" ]; then printf 'SAVE=missing\\n';",
        "elif [ ! -r \"$file\" ]; then printf 'SAVE=unreadable\\n';",
        "else",
        "  current=$(nft list ruleset 2>/dev/null | grep -v '^#' | grep -v '^[[:space:]]*$')",
        "  saved=$(grep -v '^#' \"$file\" 2>/dev/null | grep -v '^[[:space:]]*$' | grep -v '^flush ruleset')",
        "  if [ -z \"$current\" ]; then printf 'SAVE=unknown\\n';",
        "  elif [ \"$current\" = \"$saved\" ]; then printf 'SAVE=saved\\n';",
        "  else printf 'SAVE=pending\\n'; fi",
        "fi",
        "if systemctl is-enabled nftables.service >/dev/null 2>&1; then printf 'BOOT=enabled\\n'; else printf 'BOOT=disabled\\n'; fi",
        "if [ -r \"$file\" ]; then",
        "  grep -qE '^[[:space:]]*flush[[:space:]]+ruleset' \"$file\" && printf 'FLUSH=ruleset\\n' || printf 'FLUSH=none\\n';",
        "  declared=$(grep -oE '^[[:space:]]*table[[:space:]]+[A-Za-z0-9_]+[[:space:]]+[A-Za-z0-9_-]+' \"$file\" 2>/dev/null | awk '{print $2\" \"$3}' | sort -u | tr '\\n' ',');",
        "  printf 'TABLES=%s\\n' \"$declared\";",
        "fi",
    ].join("\n");

    const result = await ctx.read(["sh", "-c", script]);
    return parsePersistenceReport(result.ok ? result.output : "", { mechanism: "nftables.service", file: "/etc/nftables.conf" });
}

function parseFirewalldListAll(output) {
    const info = { zone: "", active: false, items: {} };
    let currentKey = null;

    String(output || "").split(/\r?\n/).forEach(line => {
        if (!line.trim())
            return;

        const zoneMatch = line.match(/^(\S+)(?:\s+\(([^)]+)\))?\s*$/);
        if (zoneMatch && !line.startsWith(" ")) {
            info.zone = zoneMatch[1];
            info.active = zoneMatch[2] === "active";
            currentKey = null;
            return;
        }

        const keyMatch = line.match(/^\s*([a-z][a-z0-9_ -]*?)\s*:\s*(.*)$/i);
        if (keyMatch) {
            currentKey = keyMatch[1];
            info.items[currentKey] = keyMatch[2].trim();
            return;
        }

        if (currentKey)
            info.items[currentKey] = [info.items[currentKey], line.trim()].filter(Boolean).join("\n");
    });

    return info;
}

function firewalldLines(info, key) {
    return String(info.items[key] || "")
        .split(/\n/)
        .map(value => value.trim())
        .filter(Boolean);
}

function firewalldValues(info, key) {
    return firewalldLines(info, key).flatMap(value => value.split(/\s+/)).filter(Boolean);
}

function parseFirewalldStatus({ stateResult, zoneResult, runtime, permanent }) {
    const runtimeInfo = parseFirewalldListAll(runtime.ok ? runtime.output : "");
    const permanentInfo = parseFirewalldListAll(permanent.ok ? permanent.output : "");
    const running = /running/i.test(String(stateResult.output || ""));
    const zoneName = String(zoneResult.output || "").trim() || runtimeInfo.zone || permanentInfo.zone || "public";

    const permanentServices = new Set(firewalldValues(permanentInfo, "services"));
    const permanentPorts = new Set(firewalldValues(permanentInfo, "ports"));
    const permanentRich = new Set(firewalldLines(permanentInfo, "rich rules"));

    const rows = [];
    const addRows = (label, runtimeValues, permanentValues, type) => {
        const values = new Set([...runtimeValues, ...permanentValues]);
        values.forEach(value => {
            const inRuntime = runtimeValues.has(value);
            const inPermanent = permanentValues.has(value);
            const persistedLabel = inRuntime
                ? (inPermanent ? "Laufzeit + Dauerhaft" : "Nur Laufzeit")
                : "Nur dauerhaft (inaktiv)";
            rows.push({
                cells: [label, value, persistedLabel],
                delete: {
                    kind: "firewalld",
                    type,
                    value,
                    inRuntime,
                    inPermanent,
                    description: `firewalld ${label} ${value}`,
                    label: "Löschen",
                },
            });
        });
    };

    addRows("Dienst", new Set(firewalldValues(runtimeInfo, "services")), permanentServices, "service");
    addRows("Port", new Set(firewalldValues(runtimeInfo, "ports")), permanentPorts, "port");
    addRows("Rich Rules", new Set(firewalldLines(runtimeInfo, "rich rules")), permanentRich, "rich");

    ["forward-ports", "source-ports", "protocols", "icmp-blocks"].forEach(key => {
        firewalldValues(runtimeInfo, key).forEach(value => {
            rows.push({ cells: [key, value, "-"] });
        });
    });

    const countByLabel = label => rows.filter(row => row.cells[2] === label).length;
    const runtimeOnly = countByLabel("Nur Laufzeit");
    const permanentOnly = countByLabel("Nur dauerhaft (inaktiv)");
    const blockers = [
        runtimeOnly ? `${runtimeOnly} Einträge nur zur Laufzeit` : "",
        permanentOnly ? `${permanentOnly} Einträge nur dauerhaft` : "",
    ].filter(Boolean).join(", ");
    const summary = running
        ? `firewalld aktiv; Standardzone ${zoneName}, insgesamt ${rows.length} Einträge${blockers ? ` (${blockers})` : ""}.`
        : `firewalld inaktiv; Standardzone ${zoneName}, dauerhaft konfigurierte Einträge: ${rows.length}.`;

    return {
        summary,
        statusLabel: running ? "Aktiv" : normalizeStatus(String(stateResult.output || "Inaktiv").trim()),
        tone: running ? (blockers ? "warning" : "success") : "warning",
        ruleCount: String(rows.length),
        policySummary: `Standardzone: ${zoneName}${runtimeInfo.active ? " (aktiv)" : ""}`,
        details: [
            ["Dienststatus", running ? "Aktiv" : normalizeStatus(String(stateResult.output || "Inaktiv").trim())],
            ["Standardzone", `${zoneName}${runtimeInfo.active ? " (aktiv)" : ""}`],
            runtimeInfo.items.target ? ["Ziel", runtimeInfo.items.target] : null,
            runtimeInfo.items.interfaces ? ["Schnittstellen", runtimeInfo.items.interfaces] : null,
            runtimeInfo.items.forward ? ["Weiterleitung", runtimeInfo.items.forward] : null,
            runtimeInfo.items.masquerade ? ["Masquerading", runtimeInfo.items.masquerade] : null,
            ["Eintrag", `${rows.length} Einträge${blockers ? ` (${blockers})` : ""}`],
            ["Dauerhafte Speicherung", "firewalld speichert dauerhaft nur die --permanent-Konfiguration. Einträge mit „Nur Laufzeit“ gehen beim Neuladen oder Neustart verloren; Einträge mit „Nur dauerhaft“ sind noch nicht aktiv."],
        ].filter(Boolean),
        columns: ["Typ", "Eintrag", "Dauerhafte Speicherung"],
        rows,
        emptyText: `Standardzone ${zoneName} enthält keine Dienste, Ports oder Rich Rules.`,
        chains: [],
        persist: { state: "managed", mechanism: "firewalld", file: "/etc/firewalld" },
    };
}

function parseFail2BanOverview(serviceOutput, statusOutput, serviceOk, statusOk) {
    const service = parseSystemdShow(serviceOutput);
    const jailCountMatch = statusOutput.match(/Number of jail:\s*(\d+)/i);
    const jailListMatch = statusOutput.match(/Jail list:\s*(.+)/i);
    const jailCount = jailCountMatch ? Number(jailCountMatch[1]) : 0;
    const jails = jailListMatch
        ? jailListMatch[1].split(",").map(item => item.trim()).filter(Boolean)
        : [];
    const activeState = service.ActiveState || "";
    const serviceState = activeState ? `${normalizeStatus(activeState)} / ${service.SubState || "unknown"}` : "Unbekannt";

    let summary = "Fail2Ban-Status nicht verfügbar.";
    let tone = "warning";
    let permission = false;

    if (serviceOk && statusOk) {
        summary = jails.length
            ? `Insgesamt ${jails.length} Jails: ${jails.join(", ")}.`
            : "Derzeit keine aktiven Jails.";
        tone = activeState === "active" ? "success" : "warning";
    } else if (isPermissionError(statusOutput)) {
        permission = true;
        summary = "Fail2Ban-Socket benötigt Administratorrechte. Diese Sitzung kann nur den Dienststatus anzeigen.";
    } else if (!statusOk) {
        summary = summarizeOutput(statusOutput, false);
        tone = "danger";
    }

    return {
        jailCount,
        jails: permission ? [] : jails,
        serviceState,
        summary,
        tone,
        permission,
        details: [
            ["Dienst", service.Id || "fail2ban.service"],
            service.Description ? ["Beschreibung", service.Description] : null,
            service.ActiveState ? ["Betriebsstatus", normalizeStatus(service.ActiveState)] : null,
            service.SubState ? ["Unterstatus", service.SubState] : null,
            service.UnitFileState ? ["Startverhalten", normalizeStatus(service.UnitFileState)] : null,
            service.LoadState ? ["Ladestatus", normalizeStatus(service.LoadState)] : null,
            permission ? ["jail", "Zum Lesen der Jail-Liste sind Administratorrechte erforderlich."] : null,
            ["Anzahl der Jails", permission ? "Administratorrechte erforderlich" : String(jailCount)],
            !permission && jails.length ? ["Jail-Liste", jails.join(", ")] : null,
        ].filter(Boolean),
    };
}

function parseFail2BanJail(output, jailName) {
    const detailMap = {};
    String(output || "").split(/\r?\n/).forEach(line => {
        const cleaned = line.replace(/^[\s|`-]+/, "").trim();
        if (!cleaned.includes(":"))
            return;

        const index = cleaned.indexOf(":");
        const key = cleaned.slice(0, index).trim();
        const value = cleaned.slice(index + 1).trim();
        if (key)
            detailMap[key] = value;
    });

    const bannedIps = (detailMap["Banned IP list"] || "")
        .split(/\s+/)
        .map(item => item.trim())
        .filter(Boolean);

    return {
        name: output.match(/Status for the jail:\s*(.+)/i)?.[1]?.trim() || jailName,
        metrics: [
            { label: "Aktuell fehlgeschlagen", value: detailMap["Currently failed"] || "0" },
            { label: "Aktuell gesperrt", value: detailMap["Currently banned"] || "0" },
            { label: "Sperren insgesamt", value: detailMap["Total banned"] || "0" },
        ],
        details: [
            ["Fehlversuche insgesamt", detailMap["Total failed"] || "0"],
            detailMap["File list"] ? ["Protokolldatei", detailMap["File list"]] : null,
            detailMap["Banned IP list"] ? ["Gesperrte IP-Adressen", detailMap["Banned IP list"]] : null,
        ].filter(Boolean),
        bannedIps,
        summary: `Jail ${jailName} geladen. Aktuell gesperrte IP-Adressen: ${detailMap["Currently banned"] || "0"}.`,
    };
}

function backendCapabilities() {
    if (state.firewallReadOnly)
        return [];

    return getFirewallBackend().capabilities || [];
}

function canFirewall(capability) {
    return isWritable() && backendCapabilities().includes(capability);
}

function visibleFirewallRows(rows) {
    if (canFirewall("deleteRule"))
        return rows;

    return rows.map(row => ({ cells: row.cells }));
}

function renderFirewallPersistState() {
    const callout = getElement("firewall-persist-callout");
    if (!callout)
        return;

    const persist = state.firewallPersist;
    const state_ = persist?.state;
    const lines = [];

    if (persist?.blocked && persist.blockedReason)
        lines.push(persist.blockedReason);
    else if (persist && state_ !== "saved" && state_ !== "managed") {
        const messages = {
            pending: `Laufzeitregeln unterscheiden sich von der gespeicherten Datei (${persist.file || "Unbekannte Datei"}).`,
            missing: `Keine Datei zur dauerhaften Speicherung gefunden${persist.file ? ` (${persist.file})` : ""}.`,
            unreadable: `Datei zur dauerhaften Speicherung nicht lesbar${persist.file ? ` (${persist.file})` : ""}, Zur Überprüfung sind Administratorrechte erforderlich.`,
            unsupported: "Keine dauerhafte Speicherung erkannt. Die Regeln gelten nur zur Laufzeit.",
            unknown: "Die dauerhafte Speicherung der Regeln konnte nicht bestätigt werden.",
        };
        lines.push(messages[state_] || messages.unknown);
        if (persist.loadedAtBoot === false)
            lines.push("Kein Laden beim Systemstart erkannt. Auch gespeicherte Regeln werden nach einem Neustart nicht wirksam.");
    }

    lines.push(...(state.firewallNotices || []));

    callout.textContent = lines.join("\n");
    callout.hidden = !lines.length;
    callout.classList.remove("tone-success", "tone-warning", "tone-danger");
    callout.classList.add("tone-warning");
}

function renderFirewallStatus(parsed) {
    renderFirewallInstallState(false);
    setText("firewall-backend-label", getFirewallBackend().label);
    setText("firewall-summary-copy", parsed.summary);
    setText("firewall-policy-summary", parsed.policySummary);
    setStatusText("firewall-status-pill", parsed.statusLabel, parsed.tone);
    renderDetailList("firewall-details", parsed.details, "Keine Firewall-Details erkannt.");
    state.firewallChains = parsed.chains || [];
    state.firewallPersist = parsed.persist || null;
    state.firewallNotices = parsed.notices || [];
    state.firewallReadOnly = parsed.readOnly === true;
    state.firewallManager = parsed.manager || "";
    state.firewallRules.columns = parsed.columns;
    state.firewallRules.rows = visibleFirewallRows(parsed.rows);
    state.firewallRules.emptyText = parsed.emptyText;
    state.firewallRules.page = 1;
    renderFirewallPersistState();
    renderFirewallRulesTable();
    updateFirewallActionBar();
}

function renderFirewallError(message) {
    renderFirewallInstallState(false);
    setText("firewall-summary-copy", summarizeOutput(message, false));
    setText("firewall-policy-summary", "Statusaktualisierung fehlgeschlagen.");
    setStatusText("firewall-status-pill", "Aktualisierung fehlgeschlagen", "danger");
    renderDetailList("firewall-details", [["Fehler", summarizeOutput(message, false)]], "Statusaktualisierung fehlgeschlagen.");
    state.firewallChains = [];
    state.firewallPersist = null;
    state.firewallNotices = [];
    state.firewallReadOnly = false;
    state.firewallManager = "";
    state.firewallRules.columns = ["Status"];
    state.firewallRules.rows = [];
    state.firewallRules.emptyText = "Die Regelliste konnte nicht gelesen werden.";
    state.firewallRules.page = 1;
    renderFirewallPersistState();
    renderFirewallRulesTable();
    updateFirewallActionBar();
}

function renderFirewallPermission(parsed) {
    renderFirewallInstallState(false);
    const backend = getFirewallBackend();
    setText("firewall-backend-label", backend.label);
    setText("firewall-summary-copy", parsed.summary);
    setText("firewall-policy-summary", "Zum Lesen der Regeln sind Administratorrechte erforderlich.");
    setStatusText("firewall-status-pill", "Administratorrechte erforderlich", "warning");
    renderDetailList("firewall-details", parsed.details || [["Berechtigung", parsed.summary]], "Administratorrechte erforderlich.");
    state.firewallChains = [];
    state.firewallPersist = parsed.persist || null;
    state.firewallNotices = [];
    state.firewallReadOnly = false;
    state.firewallManager = "";
    state.firewallRules.columns = ["Status"];
    state.firewallRules.rows = [];
    state.firewallRules.emptyText = "Zum Anzeigen der Regeln sind Administratorrechte erforderlich.";
    state.firewallRules.page = 1;
    renderFirewallPersistState();
    renderFirewallRulesTable();
    updateFirewallActionBar();
}

function renderFirewallMissing() {
    const tool = getCurrentFirewallTool();
    renderFirewallInstallState(true);
    setText("firewall-backend-label", tool.label);
    setText("firewall-policy-summary", `${tool.label} nicht installiert.`);
    state.firewallChains = [];
    state.firewallPersist = null;
    state.firewallNotices = [];
    state.firewallReadOnly = false;
    state.firewallManager = "";
    state.firewallRules.columns = ["Status"];
    state.firewallRules.rows = [];
    state.firewallRules.emptyText = `${tool.label} nicht installiert.`;
    state.firewallRules.page = 1;
    renderFirewallPersistState();
    renderFirewallRulesTable();
    updateFirewallActionBar();
}

function renderFail2BanStatus(parsed) {
    renderFail2BanInstallState(false);
    setText("fail2ban-service-state", parsed.serviceState);
    setText("fail2ban-service-copy", parsed.summary);
    setText("fail2ban-jail-count", parsed.permission ? "Administratorrechte erforderlich" : String(parsed.jailCount));
    setStatusText("fail2ban-service-pill", parsed.permission ? "Administratorrechte erforderlich" : parsed.serviceState, parsed.permission ? "warning" : parsed.tone);
    renderDetailList("fail2ban-details", parsed.details, "Kein Fail2Ban-Gesamtstatus verfügbar.");
    renderTokenRow("fail2ban-jail-list", parsed.jails, {
        clickable: true,
        emptyText: parsed.permission ? "Administratorrechte erforderlich" : "Keine Jails",
        onClick: jail => {
            fillJailInputs(jail);
            loadFail2BanJail(jail);
        },
    });

    if (parsed.permission)
        clearFail2BanJail("Zum Anzeigen der Jail-Details sind Administratorrechte erforderlich.");
}

function renderFail2BanMissing() {
    renderFail2BanInstallState(true);
    setText("fail2ban-service-state", "Nicht installiert");
    setText("fail2ban-service-copy", "Fail2Ban nicht installiert.");
    setText("fail2ban-jail-count", "--");
    clearFail2BanJail("Fail2Ban nicht installiert.");
}

function renderFail2BanJail(parsed, tone = "success") {
    state.currentJail = parsed.name;
    setText("fail2ban-current-jail", parsed.name);
    setText("fail2ban-current-jail-copy", parsed.summary);
    setStatusText("fail2ban-jail-pill", parsed.name, tone);
    renderMetricCards("fail2ban-jail-metrics", parsed.metrics);
    renderDetailList("fail2ban-jail-details", parsed.details, "Keine Jail-Details verfügbar.");
    renderTokenRow("fail2ban-banned-ips", parsed.bannedIps, {
        emptyText: "Derzeit keine gesperrten IP-Adressen",
    });
    fillJailInputs(parsed.name);
}

function clearFail2BanJail(message) {
    state.currentJail = "";
    setText("fail2ban-current-jail", "Nicht ausgewählt");
    setText("fail2ban-current-jail-copy", message);
    setStatusText("fail2ban-jail-pill", "Nicht ausgewählt");
    renderMetricCards("fail2ban-jail-metrics", []);
    renderDetailList("fail2ban-jail-details", [], message);
    renderTokenRow("fail2ban-banned-ips", [], {
        emptyText: "Derzeit keine gesperrten IP-Adressen",
    });
}

function showCommandResult(prefix, label, text, ok = true, summaryOverride = "") {
    const summary = summaryOverride || summarizeOutput(text, ok);
    setStatusText(`${prefix}-command-label`, label, ok ? "success" : "danger");
    setAlert(`${prefix}-result-summary`, {
        title: summary,
        detail: text && text !== summary ? text : "",
        variant: ok ? "success" : "danger",
    });
}

async function execute(prefix, label, argsOrScript, options = {}) {
    const commandLabel = Array.isArray(argsOrScript) ? argsOrScript.join(" ") : argsOrScript;
    const shouldUpdateResult = options.updateResult !== false;

    if (shouldUpdateResult)
        showCommandResult(prefix, label, `Wird ausgeführt...\n\n${commandLabel}`, true, "Befehl wird ausgeführt...");

    const result = await capture(argsOrScript, options);
    if (shouldUpdateResult) {
        showCommandResult(prefix, result.ok ? label : `${label} Fehlgeschlagen`, result.output, result.ok, options.summary);
        refreshSecurityLogs();
    }

    return result;
}

async function executeSteps(prefix, steps) {
    let result = { ok: true, output: "" };
    for (const step of steps) {
        result = await execute(prefix, step.label, step.args, { summary: step.summary });
        if (!result.ok)
            return result;
    }

    return result;
}

async function refreshFirewallStatus() {
    return withRefreshLock("firewall", async () => {
        const backend = getFirewallBackend();
        // Tool detection is unprivileged; the read itself degrades to a
        // permission notice when the session cannot escalate.
        const installed = await checkToolInstalled(backend.toolId, { force: true });
        if (!installed) {
            renderFirewallMissing();
            return;
        }

        renderFirewallInstallState(false);
        setText("firewall-summary-copy", "Firewall-Status wird aktualisiert...");
        setStatusText("firewall-status-pill", "Wird geladen", "loading");

        const parsed = await backend.read(FIREWALL_CONTEXT);
        if (parsed.kind === "permission") {
            renderFirewallPermission(parsed);
            return;
        }

        if (parsed.kind === "error") {
            renderFirewallError(parsed.message);
            return;
        }

        renderFirewallStatus(parsed);
    });
}

async function refreshFail2BanStatus() {
    return withRefreshLock("fail2ban", async () => {
        const installed = await checkToolInstalled("fail2ban", { force: true });
        if (!installed) {
            renderFail2BanMissing();
            return;
        }

        renderFail2BanInstallState(false);
        setText("fail2ban-service-copy", "Fail2Ban-Status wird aktualisiert...");
        setStatusText("fail2ban-service-pill", "Wird geladen", "loading");

        const serviceName = await resolveFail2BanService();
        const [serviceResult, statusResult] = await Promise.all([
            captureRead([
                "systemctl",
                "show",
                serviceName,
                "--property=Id,Description,LoadState,ActiveState,SubState,UnitFileState,FragmentPath",
            ]),
            captureRead([getToolCommand("fail2ban"), "status"]),
        ]);

        const parsed = parseFail2BanOverview(serviceResult.output, statusResult.output, serviceResult.ok, statusResult.ok);
        renderFail2BanStatus(parsed);

        if (state.currentJail && !parsed.permission) {
            if (parsed.jails.includes(state.currentJail))
                await loadFail2BanJail(state.currentJail, { quiet: true });
            else
                clearFail2BanJail("Das ausgewählte Jail ist nicht mehr in der Liste enthalten. Bitte erneut auswählen.");
        }
    });
}

async function loadFail2BanJail(jail, options = {}) {
    const jailName = jail.trim();
    if (!jailName) {
        showCommandResult("fail2ban", "Jail-Abfrage fehlgeschlagen", "Der Jail-Name darf nicht leer sein.", false);
        return;
    }

    setStatusText("fail2ban-jail-pill", "Wird geladen", "loading");
    setText("fail2ban-current-jail", jailName);
    setText("fail2ban-current-jail-copy", "Jail-Details werden geladen...");

    const result = await captureRead([getToolCommand("fail2ban"), "status", jailName]);
    if (!result.ok) {
        const permission = isPermissionError(result.output);
        const summary = permission ? "Zum Abfragen der Jail-Details sind Administratorrechte erforderlich." : summarizeOutput(result.output, false);
        setText("fail2ban-current-jail", jailName);
        setText("fail2ban-current-jail-copy", summary);
        setStatusText("fail2ban-jail-pill", permission ? "Administratorrechte erforderlich" : "Laden fehlgeschlagen", permission ? "warning" : "danger");
        renderMetricCards("fail2ban-jail-metrics", []);
        renderDetailList("fail2ban-jail-details", [["Fehler", summary]], "Jail-Abfrage fehlgeschlagen.");
        renderTokenRow("fail2ban-banned-ips", [], {
            emptyText: "Derzeit keine gesperrten IP-Adressen",
        });
        if (!options.quiet)
            showCommandResult("fail2ban", `jail: ${jailName} Fehlgeschlagen`, result.output, false, summary);
        return;
    }

    const parsed = parseFail2BanJail(result.output, jailName);
    renderFail2BanJail(parsed);
    if (!options.quiet)
        showCommandResult("fail2ban", `jail: ${jailName}`, result.output, true, parsed.summary);
}

function readRememberedFirewallBackend() {
    try {
        return window.localStorage.getItem(FIREWALL_BACKEND_STORAGE_KEY) || "";
    } catch (error) {
        console.debug("Unable to read remembered firewall backend", error);
        return "";
    }
}

function rememberFirewallBackend(backend) {
    try {
        window.localStorage.setItem(FIREWALL_BACKEND_STORAGE_KEY, backend);
    } catch (error) {
        console.debug("Unable to remember firewall backend", error);
    }
}

function renderFirewallBackendToggle() {
    const container = getElement("firewall-backend-toggle");
    const group = container?.querySelector(".pf-v6-c-toggle-group");
    if (!container || !group)
        return;

    const available = state.firewallBackends.length ? state.firewallBackends : [state.firewallBackend];
    container.hidden = available.length < 2;
    group.replaceChildren();

    available.forEach(id => {
        const backend = FIREWALL_BACKENDS[id];
        if (!backend)
            return;

        const item = document.createElement("div");
        item.className = "pf-v6-c-toggle-group__item";

        const button = document.createElement("button");
        button.type = "button";
        button.className = "pf-v6-c-toggle-group__button backend-button";
        button.dataset.backend = id;
        const active = id === state.firewallBackend;
        button.classList.toggle("pf-m-selected", active);
        button.setAttribute("aria-pressed", active ? "true" : "false");

        const text = document.createElement("span");
        text.className = "pf-v6-c-toggle-group__text";
        text.textContent = backend.label;
        button.append(text);
        item.append(button);
        group.append(item);
    });
}

async function detectAvailableFirewallBackends() {
    const detected = await Promise.all(FIREWALL_BACKEND_ORDER.map(async id => {
        const backend = FIREWALL_BACKENDS[id];
        const installed = await checkToolInstalled(backend.toolId);
        return installed ? id : null;
    }));

    return detected.filter(Boolean);
}

async function resolvePreferredFirewallBackend(available) {
    if (available.includes("firewalld")) {
        const result = await captureRead([getToolCommand("firewalld"), "--state"]);
        if (result.ok && /running/i.test(result.output))
            return "firewalld";
    }

    if (available.includes("ufw")) {
        const result = await captureRead(["systemctl", "is-enabled", "ufw.service"]);
        if (result.ok && /enabled/i.test(result.output))
            return "ufw";
    }

    if (available.includes("nftables")) {
        const result = await captureRead(["systemctl", "is-enabled", "nftables.service"]);
        if (result.ok && /enabled/i.test(result.output))
            return "nftables";
    }

    // iptables is always meaningful (Docker and most tools write rules through
    // it, even when that lands in the nftables kernel implementation).
    if (available.includes("iptables"))
        return "iptables";

    return available[0] || "ufw";
}

async function initFirewallBackends() {
    state.firewallBackends = await detectAvailableFirewallBackends();

    const remembered = readRememberedFirewallBackend();
    const preferred = state.firewallBackends.includes(remembered)
        ? remembered
        : await resolvePreferredFirewallBackend(state.firewallBackends);

    switchFirewallBackend(preferred, { refresh: false, remember: false });
    state.firewallBackendsReady = true;

    if (state.superuserAllowed !== null)
        await refreshSecurityPage();
}

function switchFirewallBackend(backendId, options = {}) {
    state.firewallBackend = FIREWALL_BACKENDS[backendId] ? backendId : "ufw";
    if (options.remember !== false)
        rememberFirewallBackend(state.firewallBackend);

    renderFirewallBackendToggle();

    // Only reveal/hide the settings vs install state once detection has actually run.
    // While still null (not yet checked) keep both hidden so we never flash the
    // operations UI for a tool that may turn out to be missing.
    if (state.toolInstalled[state.firewallBackend] !== null)
        renderFirewallInstallState(state.toolInstalled[state.firewallBackend] === false);
    updateFirewallActionBar();
    setText("firewall-backend-label", getFirewallBackend().label);
    if (state.firewallDialog.open)
        closeFirewallDialog();
    if (options.refresh !== false)
        refreshFirewallStatus();
}

function getFormValue(form, name) {
    const field = form.elements.namedItem(name);
    return typeof field?.value === "string" ? field.value.trim() : "";
}

function fillJailInputs(jail) {
    const jailInput = document.getElementById("fail2ban-jail-input");
    const unbanInput = document.getElementById("fail2ban-unban-jail-input");
    if (jailInput)
        jailInput.value = jail;
    if (unbanInput)
        unbanInput.value = jail;
}

function updateFirewallActionBar() {
    const backend = getFirewallBackend();
    const writable = isWritable();

    // A backend that cannot do something hides the control; a session that is
    // not admin keeps it visible but disabled.
    const applyPermission = button => {
        if (!button)
            return;
        button.disabled = !writable;
        if (writable)
            button.removeAttribute("title");
        else
            button.title = ADMIN_REQUIRED_HINT;
    };

    const toggle = (id, capability) => {
        const button = getElement(id);
        if (!button)
            return;
        const supported = backend.capabilities.includes(capability) && !state.firewallReadOnly;
        button.hidden = !supported;
        if (supported)
            applyPermission(button);
    };

    toggle("firewall-enable-button", "enable");
    toggle("firewall-disable-button", "disable");
    toggle("firewall-reload-button", "reload");
    toggle("firewall-add-button", "addRule");

    const addButton = getElement("firewall-add-button");
    if (addButton)
        addButton.textContent = backend.addRuleLabel;

    const persistButton = getElement("firewall-persist-button");
    if (persistButton) {
        const persistState = state.firewallPersist?.state;
        const needsPersist = backend.capabilities.includes("persist") && !state.firewallReadOnly &&
            !state.firewallPersist?.blocked &&
            persistState && persistState !== "saved" && persistState !== "managed";
        persistButton.hidden = !needsPersist;
        if (needsPersist)
            applyPermission(persistButton);
    }
}

function resetFirewallDialog() {
    state.firewallDialog = {
        open: false,
        mode: "",
        busy: false,
        error: "",
    };
}

function updateFirewallDialog(patch) {
    state.firewallDialog = {
        ...state.firewallDialog,
        ...patch,
    };
    renderFirewallDialog();
}

function setFirewallRuleActionOptions(backend) {
    const select = getElement("firewall-rule-action");
    if (!select)
        return;

    select.replaceChildren();
    (backend.actionOptions || []).forEach(option => {
        const element = document.createElement("option");
        element.value = option.value;
        element.textContent = option.label;
        select.append(element);
    });
}

function renderFirewallChainOptions(backend) {
    const select = getElement("firewall-rule-chain");
    if (!select)
        return;

    const chains = state.firewallChains?.length
        ? state.firewallChains
        : (backend.fallbackChains || []).map(chain => ({ value: chain, label: chain }));

    select.replaceChildren();
    chains.forEach(chain => {
        const option = document.createElement("option");
        option.value = chain.value;
        option.textContent = chain.label;
        select.append(option);
    });
}

function renderFirewallRuleForm() {
    const backend = getFirewallBackend();
    const groups = {
        action: "firewall-rule-action-group",
        chain: "firewall-rule-chain-group",
        port: "firewall-rule-port-group",
        protocol: "firewall-rule-protocol-group",
        source: "firewall-rule-source-group",
    };

    Object.entries(groups).forEach(([field, id]) => {
        setHidden(id, !backend.fields.includes(field));
    });

    setFirewallRuleActionOptions(backend);
    renderFirewallChainOptions(backend);
}

function renderFirewallDialog() {
    const dialog = getElement("firewall-modal");
    const title = getElement("firewall-modal-title");
    const copy = getElement("firewall-modal-copy");
    const form = getElement("firewall-rule-form");
    const alert = getElement("firewall-modal-alert");
    const submit = getElement("firewall-modal-submit");
    const cancel = getElement("firewall-modal-cancel");
    const close = getElement("firewall-modal-close");

    if (!dialog || !title || !copy || !form || !alert || !submit || !cancel || !close)
        return;

    const current = state.firewallDialog;
    dialog.hidden = !current.open;
    if (!current.open)
        return;

    const backend = getFirewallBackend();
    const hint = [backend.dialogHint, ...(state.firewallNotices || [])].filter(Boolean).join(" ");
    title.textContent = backend.dialogTitle || backend.addRuleLabel;
    copy.hidden = !hint;
    copy.textContent = hint;
    form.hidden = false;
    setAlert("firewall-modal-alert", current.error ? { title: current.error, variant: "danger" } : {});
    submit.textContent = current.busy ? "Wird ausgeführt..." : "Anwenden";
    submit.disabled = current.busy;
    cancel.disabled = current.busy;
    close.disabled = current.busy;
    form.querySelectorAll("input, select").forEach(field => {
        field.disabled = current.busy;
    });
}

function openFirewallRuleDialog() {
    const form = getElement("firewall-rule-form");
    if (form)
        form.reset();

    renderFirewallRuleForm();
    const portInput = getElement("firewall-rule-port");
    if (portInput)
        portInput.removeAttribute("aria-invalid");
    updateFirewallDialog({
        open: true,
        mode: "add-rule",
        busy: false,
        error: "",
    });
}

function closeFirewallDialog() {
    resetFirewallDialog();
    renderFirewallDialog();
}

function renderConfirmDialog() {
    const dialog = getElement("security-confirm-dialog");
    const title = getElement("security-confirm-title");
    const submit = getElement("security-confirm-submit");
    const cancel = getElement("security-confirm-cancel");

    if (!dialog || !title || !submit || !cancel)
        return;

    const current = state.confirmDialog;
    dialog.hidden = !current.open;
    if (!current.open)
        return;

    title.textContent = current.title;
    submit.textContent = current.confirmLabel;
    submit.className = `pf-v6-c-button pf-m-${current.variant}`;
    setAlert("security-confirm-alert", current.message ? { title: current.message, variant: "warning" } : {});
}

function settleConfirmDialog(confirmed) {
    const { resolve } = state.confirmDialog;
    state.confirmDialog = { open: false, title: "", message: "", confirmLabel: "Bestätigen", variant: "danger", resolve: null };
    renderConfirmDialog();
    if (resolve)
        resolve(confirmed);
}

// Standard Cockpit confirmation: Modal + inline warning Alert + danger primary
// button on the left, link Cancel on the right. Deliberately not window.confirm.
function confirmAction({ title, message = "", confirmLabel = "Bestätigen", variant = "danger" }) {
    if (state.confirmDialog.open)
        settleConfirmDialog(false);

    return new Promise(resolve => {
        state.confirmDialog = { open: true, title, message, confirmLabel, variant, resolve };
        renderConfirmDialog();
    });
}

async function deleteFirewallRule(rule) {
    if (!rule || rule.disabled || !canFirewall("deleteRule"))
        return;

    const plan = getFirewallBackend().buildDeleteRule(FIREWALL_CONTEXT, rule);
    if (!plan)
        return;

    const managerWarning = state.firewallManager
        ? ` ${state.firewallManager} verwaltet die lokalen Regeln. Änderungen können beim Neuladen überschrieben werden.`
        : "";
    const confirmed = await confirmAction({
        title: `Löschen ${rule.description || rule.value}`,
        message: `Die Regel wird sofort und unwiderruflich gelöscht.${managerWarning}`,
        confirmLabel: "Löschen",
        variant: "danger",
    });
    if (!confirmed)
        return;

    const result = await executeSteps("firewall", plan.steps);
    if (result.ok)
        await refreshFirewallStatus();
}

const PORT_PATTERN = /^\d+(?:[:-]\d+)?$/;
const SOURCE_PATTERN = /^[0-9a-fA-F.:]+(?:\/\d{1,3})?$/;

function validateFirewallRuleForm(backend, values) {
    if (!PORT_PATTERN.test(values.port))
        return { field: "firewall-rule-port", message: "Ungültiger Port. Erlaubt sind 22, 22:80 oder 22-80." };

    if (values.source && !SOURCE_PATTERN.test(values.source))
        return { field: "firewall-rule-source", message: "Ungültige Quelle. Gib eine IP-Adresse oder ein CIDR-Netz ein oder lasse das Feld leer." };

    if (backend.fields.includes("chain") && !values.chain)
        return { field: "firewall-rule-chain", message: "Bitte zuerst die Kette für die Regel auswählen." };

    return null;
}

async function handleFirewallDialogSubmit() {
    if (!state.firewallDialog.open || state.firewallDialog.busy)
        return;

    if (!isWritable()) {
        updateFirewallDialog({ error: "Zum Ändern der Firewall sind Administratorrechte erforderlich." });
        return;
    }

    const backend = getFirewallBackend();
    const form = getElement("firewall-rule-form");
    if (!form)
        return;

    const values = {
        action: getFormValue(form, "action") || backend.actionOptions?.[0]?.value || "",
        chain: getFormValue(form, "chain"),
        port: getFormValue(form, "port"),
        protocol: getFormValue(form, "protocol") || "tcp",
        source: getFormValue(form, "source"),
    };

    const invalid = validateFirewallRuleForm(backend, values);
    if (invalid) {
        ["firewall-rule-port", "firewall-rule-source", "firewall-rule-chain"].forEach(id => getElement(id)?.removeAttribute("aria-invalid"));
        getElement(invalid.field)?.setAttribute("aria-invalid", "true");
        updateFirewallDialog({ error: invalid.message });
        return;
    }

    const plan = backend.buildAddRule(FIREWALL_CONTEXT, values);
    if (!plan) {
        updateFirewallDialog({ error: "Bitte den Status aktualisieren und die Kette für die Regel auswählen." });
        return;
    }

    updateFirewallDialog({ busy: true, error: "" });
    const result = await executeSteps("firewall", plan.steps);
    if (!result.ok) {
        updateFirewallDialog({
            busy: false,
            error: summarizeOutput(result.output, false),
        });
        return;
    }

    closeFirewallDialog();
    form.reset();
    await refreshFirewallStatus();
}

async function handleQuickAction(action) {
    if (!isWritable())
        return;

    if (action.startsWith("fail2ban")) {
        const fail2banService = state.fail2banService || "fail2ban.service";
        const actions = {
            "fail2ban-start": () => execute("fail2ban", "Fail2Ban starten", ["systemctl", "start", fail2banService]),
            "fail2ban-stop": () => execute("fail2ban", "Fail2Ban stoppen", ["systemctl", "stop", fail2banService]),
            "fail2ban-restart": () => execute("fail2ban", "Fail2Ban neu starten", ["systemctl", "restart", fail2banService]),
            "fail2ban-reload": () => execute("fail2ban", "Fail2Ban neu laden", [getToolCommand("fail2ban"), "reload"]),
        };

        const handler = actions[action];
        if (!handler)
            return;

        await handler();
        await refreshFail2BanStatus();
        return;
    }

    const step = getFirewallBackend().quickActions(FIREWALL_CONTEXT)[action];
    if (!step)
        return;

    if (step.confirm) {
        const confirmed = await confirmAction({
            title: step.label,
            message: step.confirm,
            confirmLabel: "Fortfahren",
            variant: step.danger ? "danger" : "primary",
        });
        if (!confirmed)
            return;
    }

    const steps = step.steps || [{ args: step.args, label: step.label }];
    const result = await executeSteps("firewall", steps);
    if (result.ok)
        await refreshFirewallStatus();
}

async function handleFail2BanJail(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const jail = getFormValue(form, "jail");
    await loadFail2BanJail(jail);
}

async function handleFail2BanUnban(event) {
    event.preventDefault();
    if (!isWritable())
        return;

    const form = event.currentTarget;
    const jail = getFormValue(form, "jail");
    const ip = getFormValue(form, "ip");

    if (!jail || !ip) {
        showCommandResult("fail2ban", "Entsperren fehlgeschlagen", "Jail und IP-Adresse dürfen nicht leer sein.", false);
        return;
    }

    fillJailInputs(jail);
    await execute("fail2ban", "Fail2Ban: IP-Adresse entsperren", [getToolCommand("fail2ban"), "set", jail, "unbanip", ip]);
    form.reset();
    fillJailInputs(jail);
    await refreshFail2BanStatus();
    await loadFail2BanJail(jail, { quiet: true });
}

function bindEvents() {
    document.getElementById("firewall-backend-toggle")?.addEventListener("click", event => {
        const button = event.target.closest?.(".backend-button");
        if (button)
            switchFirewallBackend(button.dataset.backend);
    });

    document.querySelectorAll("[data-action]").forEach(button => {
        button.addEventListener("click", () => handleQuickAction(button.dataset.action));
    });

    document.querySelectorAll("[data-install-tool]").forEach(button => {
        button.addEventListener("click", () => openInstallDialog(button.dataset.installTool));
    });

    document.getElementById("security-readonly-action")?.addEventListener("click", requestSuperuserAccess);
    document.getElementById("security-auth-form")?.addEventListener("submit", handleSuperuserDialogSubmit);
    document.getElementById("security-auth-form")?.addEventListener("input", handleSuperuserDialogInput);
    document.getElementById("security-auth-form")?.addEventListener("change", handleSuperuserDialogInput);
    document.getElementById("security-auth-cancel")?.addEventListener("click", () => closeSuperuserDialog());
    document.getElementById("security-auth-close")?.addEventListener("click", () => closeSuperuserDialog());
    document.getElementById("firewall-add-button")?.addEventListener("click", openFirewallRuleDialog);
    document.getElementById("firewall-modal-submit")?.addEventListener("click", handleFirewallDialogSubmit);
    document.getElementById("firewall-modal-cancel")?.addEventListener("click", closeFirewallDialog);
    document.getElementById("firewall-modal-close")?.addEventListener("click", closeFirewallDialog);
    document.getElementById("firewall-rule-form")?.addEventListener("submit", event => {
        event.preventDefault();
        handleFirewallDialogSubmit();
    });
    document.getElementById("firewall-modal")?.addEventListener("click", event => {
        if (event.target?.id === "firewall-modal")
            closeFirewallDialog();
    });
    document.getElementById("security-install-submit")?.addEventListener("click", handleInstallDialogSubmit);
    document.getElementById("security-install-cancel")?.addEventListener("click", closeInstallDialog);
    document.getElementById("security-install-close")?.addEventListener("click", closeInstallDialog);
    document.getElementById("security-install-dialog")?.addEventListener("click", event => {
        if (event.target?.id === "security-install-dialog")
            closeInstallDialog();
    });
    document.getElementById("security-auth-dialog")?.addEventListener("click", event => {
        if (event.target?.id === "security-auth-dialog")
            closeSuperuserDialog();
    });
    document.getElementById("security-confirm-submit")?.addEventListener("click", () => settleConfirmDialog(true));
    document.getElementById("security-confirm-cancel")?.addEventListener("click", () => settleConfirmDialog(false));
    document.getElementById("security-confirm-dialog")?.addEventListener("click", event => {
        if (event.target?.id === "security-confirm-dialog")
            settleConfirmDialog(false);
    });
    document.getElementById("firewall-rules-prev")?.addEventListener("click", () => {
        state.firewallRules.page = Math.max(1, state.firewallRules.page - 1);
        renderFirewallRulesTable();
    });
    document.getElementById("firewall-rules-next")?.addEventListener("click", () => {
        const totalPages = getFirewallRuleTotalPages();
        state.firewallRules.page = Math.min(totalPages, state.firewallRules.page + 1);
        renderFirewallRulesTable();
    });
    document.getElementById("firewall-rules-page-go")?.addEventListener("click", () => {
        jumpToFirewallRulesPage(document.getElementById("firewall-rules-page-jump")?.value);
    });
    document.getElementById("firewall-rules-page-jump")?.addEventListener("change", event => {
        jumpToFirewallRulesPage(event.target.value);
    });
    document.getElementById("firewall-rules-page-jump")?.addEventListener("keydown", event => {
        if (event.key !== "Enter")
            return;

        event.preventDefault();
        jumpToFirewallRulesPage(event.target.value);
    });
    document.getElementById("security-log-source-toggle")?.addEventListener("click", () => {
        positionSecurityLogMenu();
        toggleSecurityLogMenu();
    });
    document.addEventListener("click", event => {
        const menu = document.getElementById("security-log-menu");
        const toggle = document.getElementById("security-log-source-toggle");
        if (menu && !menu.hidden && toggle && !toggle.contains(event.target) && !menu.contains(event.target))
            closeSecurityLogMenu();
    });
    document.getElementById("security-log-refresh")?.addEventListener("click", refreshSecurityLogs);
    document.getElementById("security-log-view-all")?.addEventListener("click", () => {
        cockpit.jump(getSecurityLogUrl());
    });
    document.getElementById("fail2ban-jail-form")?.addEventListener("submit", handleFail2BanJail);
    document.getElementById("fail2ban-unban-form")?.addEventListener("submit", handleFail2BanUnban);

    document.addEventListener("visibilitychange", () => {
        if (document.hidden) {
            stopAutoRefresh();
            return;
        }

        if (state.superuserAllowed !== null) {
            refreshSecurityPage();
            startAutoRefresh();
        }
    });

    document.addEventListener("keydown", event => {
        if (event.key === "Escape" && state.confirmDialog.open) {
            settleConfirmDialog(false);
            return;
        }

        if (event.key === "Escape" && state.firewallDialog.open) {
            closeFirewallDialog();
            return;
        }

        if (event.key === "Escape" && state.installDialog.open) {
            closeInstallDialog();
            return;
        }

        if (event.key === "Escape" && state.superuserDialog.open)
            closeSuperuserDialog();
    });
}

document.addEventListener("DOMContentLoaded", async () => {
    bindEvents();
    bindDarkMode();
    initSuperuser();
    renderSecurityLogSourceOptions();
    clearFail2BanJail("Wähle ein Jail aus der Liste oder gib den Namen manuell ein.");
    renderFirewallDialog();
    renderInstallDialog();
    renderSuperuserDialog();
    renderConfirmDialog();
    renderAccessState();
    await initFirewallBackends();
});
