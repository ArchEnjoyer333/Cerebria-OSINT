// --- 1. STATE ---
let configState = {};
let modulesData = [];
let currentModuleId = null;
let currentPayload = {};

// --- 2. UI HELPERS ---
const ui = {
    set: (id, text) => {
        const el = document.getElementById(id);
        if (el) el.innerText = (text !== undefined && text !== null && text !== '') ? text : 'N/A';
    },
    html: (id, markup) => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = markup || '';
    }
};

// --- 3. DYNAMIC PIVOT BUILDER ---
function renderPivots(pivots) {
    const container = document.getElementById('pivotsContainer');
    if (!container) return;
    container.innerHTML = '';

    if (!Array.isArray(pivots) || pivots.length === 0) return;

    pivots.forEach(p => {
        const a = document.createElement('a');
        a.href = p.url;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        a.className = "text-xs font-mono font-medium px-3.5 py-2 rounded-xl bg-white/[0.03] hover:bg-white/[0.08] border border-white/[0.08] text-neutral-300 hover:text-white transition-all active:scale-95";
        a.innerText = `${p.label} ↗`;
        container.appendChild(a);
    });
}

// --- 4. RENDER STRATEGIES ---
const ModuleStrategies = {
    'ipwhois': (raw, target) => {
        ui.set('heroBadge', 'IP');
        ui.set('heroTitle', raw.ip || target);
        ui.set('heroType', `${raw.type || 'IPv4'} • Network`);
        ui.set('heroSub', `${raw.asn || 'N/A'} • ${raw.org || raw.isp || 'Autonomous System'}`);

        renderPivots([
            { label: 'BGPView', url: `https://bgp.he.net/ip/${target}` },
            { label: 'Shodan', url: `https://www.shodan.io/host/${target}` },
            { label: 'VirusTotal', url: `https://www.virustotal.com/gui/ip-address/${target}` }
        ]);

        ui.html('group1List', `
            <div class="flex justify-between items-center pt-2"><span class="text-neutral-500">Autonomous System</span><span class="text-white font-mono font-semibold">${raw.asn || 'N/A'}</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">Organization</span><span class="text-neutral-200 font-mono text-right truncate max-w-[220px]">${raw.org || 'N/A'}</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">Internet Provider</span><span class="text-neutral-200 font-mono text-right truncate max-w-[220px]">${raw.isp || 'N/A'}</span></div>
        `);

        ui.html('group2List', `
            <div class="flex justify-between items-center pt-2"><span class="text-neutral-500">Location</span><span class="text-white font-semibold">${raw.country || 'N/A'} ${raw.country_code ? `(${raw.country_code})` : ''}</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">Coordinates</span><span class="text-neutral-200 font-mono">${(raw.latitude && raw.longitude) ? `${raw.latitude}, ${raw.longitude}` : 'N/A'}</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">Timezone</span><span class="text-neutral-200 font-mono">${raw.timezone || 'N/A'}</span></div>
        `);
    },

    'phone_hlr': (raw, target) => {
        const cleanNum = (raw.e164 || target).replace(/\+/g, '');
        ui.set('heroBadge', 'TEL');
        ui.set('heroTitle', raw.international || target);
        ui.set('heroType', `${raw.line_type || 'Phone'} • ${raw.valid ? 'Valid' : 'Invalid'}`);
        ui.set('heroSub', raw.carrier || 'Unknown Telecom');

        renderPivots([
            { label: 'WhatsApp', url: `https://wa.me/${cleanNum}` },
            { label: 'Sync.me', url: `https://sync.me/search/?number=${cleanNum}` },
            { label: 'NumLookup', url: `https://www.numlookup.com/` }
        ]);

        ui.html('group1List', `
            <div class="flex justify-between items-center pt-2"><span class="text-neutral-500">Carrier Operator</span><span class="text-white font-semibold">${raw.carrier || 'N/A'}</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">Line Category</span><span class="text-neutral-200">${raw.line_type || 'N/A'}</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">E.164 Standard</span><span class="text-neutral-200 font-mono">${raw.e164 || 'N/A'}</span></div>
        `);

        ui.html('group2List', `
            <div class="flex justify-between items-center pt-2"><span class="text-neutral-500">Geographic Region</span><span class="text-white">${raw.location || 'N/A'}</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">National Standard</span><span class="text-neutral-200 font-mono">${raw.national || 'N/A'}</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">Timezones</span><span class="text-neutral-200 font-mono">${Array.isArray(raw.timezones) ? raw.timezones.join(', ') : 'N/A'}</span></div>
        `);
    },

    'subdomains': (raw, target) => {
        ui.set('heroBadge', 'DOM');
        ui.set('heroTitle', raw.domain || target);
        ui.set('heroType', `${raw.total_count || 0} Subdomains`);
        ui.set('heroSub', 'Passive CT Enumeration');

        renderPivots([
            { label: 'crt.sh', url: `https://crt.sh/?q=${target}` },
            { label: 'SecurityTrails', url: `https://securitytrails.com/domain/${target}/dns` },
            { label: 'DNSDumpster', url: `https://dnsdumpster.com/` }
        ]);

        ui.html('group1List', `
            <div class="flex justify-between items-center pt-2"><span class="text-neutral-500">Total Indexed</span><span class="text-white font-mono font-semibold">${raw.total_count || 0} records</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">Certificate Authorities</span><span class="text-neutral-200 font-mono truncate max-w-[220px]">${Array.isArray(raw.issuers) ? raw.issuers.slice(0, 2).join(', ') : 'N/A'}</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">Status</span><span class="text-emerald-400 font-mono">Validated</span></div>
        `);

        ui.html('group2List', `
            <div class="flex justify-between items-center pt-2"><span class="text-neutral-500">Target Root</span><span class="text-white font-mono">${raw.domain || target}</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">Provider</span><span class="text-neutral-200 font-mono">${raw.provider || 'crt.sh'}</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">Execution</span><span class="text-neutral-200 font-mono">Completed</span></div>
        `);
    },

    'vpn_detector': (raw, target) => {
        ui.set('heroBadge', 'SEC');
        ui.set('heroTitle', raw.ip || target);
        ui.set('heroType', `Risk: ${raw.risk_level || 'LOW'}`);
        ui.set('heroSub', `${raw.organization || 'Unknown'} • ${raw.country || 'N/A'}`);

        renderPivots([
            { label: 'IPQualityScore', url: `https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/${target}` },
            { label: 'Shodan', url: `https://www.shodan.io/host/${target}` },
            { label: 'AbuseIPDB', url: `https://www.abuseipdb.com/check/${target}` }
        ]);

        ui.html('group1List', `
            <div class="flex justify-between items-center pt-2"><span class="text-neutral-500">VPN / Proxy Flag</span><span class="text-white font-mono font-semibold">${raw.is_vpn_or_proxy ? 'YES (Active)' : 'No'}</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">Datacenter / Hosting</span><span class="text-neutral-200 font-mono">${raw.is_datacenter ? 'YES' : 'No'}</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">Threat Risk Level</span><span class="text-neutral-200 font-mono font-bold">${raw.risk_level || 'LOW'}</span></div>
        `);

        ui.html('group2List', `
            <div class="flex justify-between items-center pt-2"><span class="text-neutral-500">ISP Provider</span><span class="text-white truncate max-w-[220px]">${raw.isp || 'N/A'}</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">Organization</span><span class="text-neutral-200 truncate max-w-[220px]">${raw.organization || 'N/A'}</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">Autonomous System</span><span class="text-neutral-200 font-mono">${raw.asn || 'N/A'}</span></div>
        `);
    },

    'port_scanner': (raw, target) => {
        ui.set('heroBadge', 'NET');
        ui.set('heroTitle', raw.host || target);
        ui.set('heroType', `${raw.open_count || 0} Ports Open`);
        ui.set('heroSub', `Out of ${raw.total_scanned || 20} tested ports`);

        renderPivots([
            { label: 'Shodan', url: `https://www.shodan.io/host/${raw.host || target}` },
            { label: 'Censys', url: `https://search.censys.io/hosts/${raw.host || target}` },
            { label: 'GreyNoise', url: `https://viz.greynoise.io/ip/${raw.host || target}` }
        ]);

        ui.html('group1List', `
            <div class="flex justify-between items-center pt-2"><span class="text-neutral-500">Total Open</span><span class="text-white font-mono font-semibold">${raw.open_count || 0} ports</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">Total Closed</span><span class="text-neutral-200 font-mono">${raw.closed_count || 0} ports</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">Risk Assessment</span><span class="text-neutral-200 font-mono">${raw.risk_level || 'LOW'}</span></div>
        `);

        ui.html('group2List', `
            <div class="flex justify-between items-center pt-2"><span class="text-neutral-500">Host Scanned</span><span class="text-white font-mono">${raw.host || target}</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">Engine</span><span class="text-neutral-200 font-mono">Nmap Async Probe</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">Scan Duration</span><span class="text-neutral-200 font-mono">${raw.duration_sec || 0} sec</span></div>
        `);
    },

    'minecraft_scanner': (raw, target) => {
        ui.set('heroBadge', 'MC');
        ui.set('heroTitle', raw.target || target);
        ui.set('heroType', `${raw.total_servers_found || 0} Servers Discovered`);
        ui.set('heroSub', `${raw.total_players_online || 0} Total Players Online`);

        renderPivots([
            { label: 'NameMC', url: `https://namemc.com/search?q=${target}` },
            { label: 'Minecraft-MP', url: `https://minecraft-mp.com/` },
            { label: 'Shodan MC', url: `https://www.shodan.io/search?query=minecraft+port%3A25565` }
        ]);

        ui.html('group1List', `
            <div class="flex justify-between items-center pt-2"><span class="text-neutral-500">Hosts Scanned</span><span class="text-white font-mono font-semibold">${raw.total_scanned_hosts || 1} hosts</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">Open Port 25565</span><span class="text-neutral-200 font-mono">${raw.open_ports_count || 0} ports</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">Minecraft Instances</span><span class="text-emerald-400 font-mono font-bold">${raw.total_servers_found || 0} verified</span></div>
        `);

        ui.html('group2List', `
            <div class="flex justify-between items-center pt-2"><span class="text-neutral-500">Populated Servers</span><span class="text-white font-mono">${raw.active_servers_count || 0} active</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">Total Players Tracked</span><span class="text-neutral-200 font-mono font-semibold">${raw.total_players_online || 0}</span></div>
            <div class="flex justify-between items-center pt-3"><span class="text-neutral-500">Scan Pipeline</span><span class="text-neutral-200 font-mono">2-Stage Async TCP+SLP</span></div>
        `);
    },

    'default': (raw, target) => {
        ui.set('heroBadge', 'MOD');
        ui.set('heroTitle', target);
        ui.set('heroType', 'Generic Output');
        ui.set('heroSub', 'Dynamic Payload Inspection');
        renderPivots([]);

        const keys = Object.keys(raw).slice(0, 6);
        const half = Math.ceil(keys.length / 2);

        const g1 = keys.slice(0, half).map(k => `
            <div class="flex justify-between items-center pt-2">
                <span class="text-neutral-500 font-mono">${k}</span>
                <span class="text-white font-mono truncate max-w-[200px]">${JSON.stringify(raw[k])}</span>
            </div>
        `).join('');

        const g2 = keys.slice(half).map(k => `
            <div class="flex justify-between items-center pt-2">
                <span class="text-neutral-500 font-mono">${k}</span>
                <span class="text-white font-mono truncate max-w-[200px]">${JSON.stringify(raw[k])}</span>
            </div>
        `).join('');

        ui.html('group1List', g1 || '<div class="text-neutral-500 text-xs">No metrics</div>');
        ui.html('group2List', g2 || '<div class="text-neutral-500 text-xs">No metrics</div>');
    }
};

// --- 5. FORMATTED ATTRIBUTES GRID ---
function renderFormattedAttributes(raw) {
    const container = document.getElementById('viewFormatted');
    if (!container) return;
    container.innerHTML = '';

    if (!raw || typeof raw !== 'object') {
        container.innerHTML = `<div class="p-5 text-xs text-neutral-500 col-span-full font-mono text-center">No attributes available.</div>`;
        return;
    }

    // Кастомный рендер для Subdomains
    if (currentModuleId === 'subdomains' && Array.isArray(raw.subdomains)) {
        const meta = document.createElement('div');
        meta.className = "p-5 rounded-2xl bg-white/[0.02] border border-white/[0.04] col-span-full flex flex-wrap gap-8";
        meta.innerHTML = `
            <div><span class="text-[10px] font-mono text-neutral-500 block uppercase">Target Root</span><span class="text-sm text-white font-mono">${raw.domain || '-'}</span></div>
            <div><span class="text-[10px] font-mono text-neutral-500 block uppercase">Discovered Subdomains</span><span class="text-sm text-white font-mono">${raw.total_count || raw.subdomains.length} hosts</span></div>
        `;
        container.appendChild(meta);

        raw.subdomains.forEach(sub => {
            const item = document.createElement('a');
            item.href = `http://${sub}`;
            item.target = "_blank";
            item.rel = "noopener noreferrer";
            item.className = "p-3.5 rounded-xl bg-white/[0.02] hover:bg-white/[0.05] border border-white/[0.04] flex items-center justify-between group transition-all";
            item.innerHTML = `<span class="text-xs font-mono text-neutral-300 group-hover:text-white truncate">${sub}</span><span class="text-[10px] text-neutral-600 group-hover:text-neutral-300 ml-2">↗</span>`;
            container.appendChild(item);
        });
        return;
    }

    // Кастомный рендер для Port Scanner
    if (currentModuleId === 'port_scanner' && Array.isArray(raw.open_ports)) {
        const portsCard = document.createElement('div');
        portsCard.className = "p-6 rounded-2xl bg-white/[0.02] border border-white/[0.04] col-span-full space-y-4";

        const portsHtml = raw.open_ports.length > 0
            ? raw.open_ports.map(p => `<span class="px-3 py-1.5 rounded-xl bg-white/[0.04] border border-white/[0.08] text-xs font-mono text-neutral-200 inline-block m-1 hover:border-white/[0.2] transition-colors">${p}</span>`).join('')
            : '<span class="text-xs font-mono text-neutral-500">No open ports detected in common profile.</span>';

        portsCard.innerHTML = `
            <div class="flex justify-between items-center">
                <span class="text-[11px] font-mono uppercase tracking-wider text-neutral-500">Open Ports & Services</span>
                <span class="text-xs font-mono text-white bg-white/[0.08] px-2.5 py-1 rounded-lg">${raw.open_count || 0} active</span>
            </div>
            <div class="pt-2 flex flex-wrap gap-1">${portsHtml}</div>
        `;
        container.appendChild(portsCard);
        return;
    }

    // Кастомный рендер карточек серверов Minecraft
    if (currentModuleId === 'minecraft_scanner' && Array.isArray(raw.servers)) {
        if (raw.servers.length === 0) {
            container.innerHTML = `<div class="p-6 text-sm text-neutral-500 col-span-full font-mono text-center">No Minecraft server instances responded in the targeted range.</div>`;
            return;
        }

        raw.servers.forEach(srv => {
            const card = document.createElement('div');
            card.className = "p-5 rounded-2xl bg-white/[0.02] border border-white/[0.04] flex flex-col justify-between hover:border-white/[0.12] transition-all space-y-3 col-span-1";

            const playersBadge = srv.players_online > 0
                ? `<span class="px-2 py-0.5 rounded-md text-[10px] font-mono bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 font-bold">${srv.players_online}/${srv.players_max} Players</span>`
                : `<span class="px-2 py-0.5 rounded-md text-[10px] font-mono bg-white/[0.04] text-neutral-500">0/${srv.players_max}</span>`;

            const playerList = (srv.player_sample && srv.player_sample.length > 0)
                ? `<div class="text-[11px] font-mono text-neutral-400 truncate"><span class="text-neutral-600">Sample:</span> ${srv.player_sample.join(', ')}</div>`
                : '';

            card.innerHTML = `
                <div class="flex items-center justify-between">
                    <span class="text-sm font-mono text-white font-bold tracking-tight">${srv.host}:${srv.port}</span>
                    ${playersBadge}
                </div>
                <div class="text-xs text-neutral-300 font-mono truncate" title="${srv.motd}">
                    ${srv.motd}
                </div>
                ${playerList}
                <div class="pt-2 border-t border-white/[0.04] flex items-center justify-between text-[11px] font-mono text-neutral-500">
                    <span class="truncate max-w-[140px]">${srv.version}</span>
                    <span>${srv.latency_ms} ms</span>
                </div>
            `;
            container.appendChild(card);
        });
        return;
    }

    // Универсальный рендер по всем свойствам объекта
    let renderedCount = 0;
    for (const [key, val] of Object.entries(raw)) {
        if (val === undefined || val === null || val === "" || typeof val === 'object') continue;
        renderedCount++;

        const displayVal = typeof val === 'boolean' ? (val ? 'Yes' : 'No') : val;
        const item = document.createElement('div');
        item.className = "p-4 rounded-2xl bg-white/[0.02] border border-white/[0.04] flex flex-col justify-between hover:border-white/[0.08] transition-all";
        item.innerHTML = `
            <span class="text-[10px] font-mono uppercase tracking-wider text-neutral-500">${key.replace(/_/g, ' ')}</span>
            <span class="text-xs font-mono font-medium text-neutral-200 mt-2 break-words">${displayVal}</span>
        `;
        container.appendChild(item);
    }

    if (renderedCount === 0) {
        container.innerHTML = `<div class="p-5 text-xs text-neutral-500 col-span-full font-mono text-center">Inspect Raw JSON tab for structured output.</div>`;
    }
}

// --- 6. INITIALIZATION ---
async function initApp() {
    try {
        const res = await fetch('/api/config');
        const cfg = await res.json();
        configState = cfg;

        if (cfg.app) {
            document.title = cfg.app.tab_title || `${cfg.app.name} — OSINT`;
            ui.set('appName', cfg.app.name);
            ui.set('appStatus', `${cfg.app.status} ${cfg.app.version}`);
        }

        const hostEl = document.getElementById('serverHostBadge');
        if (hostEl) {
            hostEl.innerText = (cfg.server?.host && cfg.server?.port)
                ? `${cfg.server.host}:${cfg.server.port}`
                : (window.location.host || "127.0.0.1:3000");
        }

        // Динамические ссылки (GitHub, Docs и любые другие из конфига)
        const linksContainer = document.getElementById('dynamicLinksContainer');
        if (linksContainer && cfg.links) {
            linksContainer.innerHTML = '';
            for (const [label, url] of Object.entries(cfg.links)) {
                const a = document.createElement('a');
                a.href = url;
                a.target = "_blank";
                a.rel = "noopener noreferrer";
                a.className = "flex items-center justify-center gap-2 px-3 py-2 rounded-xl bg-white/[0.02] hover:bg-white/[0.06] border border-white/[0.05] hover:border-white/[0.1] text-xs font-mono text-neutral-300 hover:text-white transition-all duration-300 active:scale-95";
                a.innerHTML = `<span>${label.charAt(0).toUpperCase() + label.slice(1)}</span><span class="text-[10px] text-neutral-500">↗</span>`;
                linksContainer.appendChild(a);
            }
        }

        // Экран приветствия
        if (cfg.welcome) {
            if (cfg.welcome.icon) {
                const iconEl = document.getElementById('welcomeIcon');
                if (iconEl) iconEl.src = cfg.welcome.icon;
            }
            if (cfg.welcome.subtitle) {
                ui.set('welcomeSubtitle', cfg.welcome.subtitle);
            }
            if (cfg.welcome.title) {
                const accent = cfg.welcome.accent_word || "Cerebria.";
                const escapedAccent = accent.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                const formattedTitle = cfg.welcome.title.replace(
                    new RegExp(escapedAccent, 'g'),
                    `<span class="bg-white text-black px-3 py-0.5 rounded-xl inline-block mx-1 font-extrabold shadow-lg">${accent}</span>`
                );
                ui.html('welcomeTitle', formattedTitle);
            }
        }

        // Стили темы
        if (cfg.theme) {
            const root = document.documentElement;
            if (cfg.theme.bg_main) root.style.setProperty('--bg-main', cfg.theme.bg_main);
            if (cfg.theme.bg_sidebar) root.style.setProperty('--bg-sidebar', cfg.theme.bg_sidebar);
            if (cfg.theme.bg_card) root.style.setProperty('--bg-card', cfg.theme.bg_card);
            if (cfg.theme.grid_size) root.style.setProperty('--grid-size', cfg.theme.grid_size);
            if (cfg.theme.grid_opacity) root.style.setProperty('--grid-opacity', cfg.theme.grid_opacity);
        }

        modulesData = cfg.modules || [];
        renderModulesNav();
        document.getElementById('welcomeView').classList.remove('hidden-view');
    } catch (e) {
        console.error("[!] Cerebria initialization error:", e);
    }
}

function renderModulesNav() {
    const nav = document.getElementById('modulesList');
    if (!nav) return;
    nav.innerHTML = '';

    modulesData.forEach(mod => {
        const btn = document.createElement('button');
        const isActive = mod.id === currentModuleId;

        btn.disabled = !mod.enabled;
        btn.className = `w-full text-left px-4 py-3 rounded-2xl border transition-all duration-400 flex items-center justify-between group ${
            !mod.enabled ? 'text-neutral-600 cursor-not-allowed opacity-40 border-transparent' :
            isActive ? 'bg-white/[0.08] border-white/[0.15] text-white shadow-xl scale-[1.01]' : 'bg-transparent border-transparent text-neutral-400 hover:bg-white/[0.03] hover:text-neutral-200'
        }`;

        btn.onclick = () => { if (mod.enabled) selectModule(mod.id); };
        btn.innerHTML = `
            <span class="flex items-center gap-3 font-medium text-sm">
                <span class="w-1.5 h-1.5 rounded-full ${!mod.enabled ? 'bg-neutral-800' : isActive ? 'bg-white shadow-[0_0_8px_rgba(255,255,255,0.9)]' : 'bg-neutral-600 group-hover:bg-neutral-400'} transition-all"></span>
                ${mod.name}
            </span>
            <span class="text-[10px] font-mono px-2 py-0.5 rounded-md ${isActive ? 'bg-white/20 text-white' : 'bg-white/[0.03] text-neutral-500'}">${mod.tag || 'MOD'}</span>
        `;
        nav.appendChild(btn);
    });
}

function selectModule(moduleId) {
    if (currentModuleId === moduleId) {
        currentModuleId = null;
        document.getElementById('workspaceView').classList.add('hidden-view');
        document.getElementById('welcomeView').classList.remove('hidden-view');
        document.getElementById('topBar').classList.remove('opacity-100');
        document.getElementById('topBar').classList.add('opacity-0', 'pointer-events-none');
        renderModulesNav();
        return;
    }

    currentModuleId = moduleId;
    const mod = modulesData.find(m => m.id === moduleId);
    if (!mod) return;

    document.getElementById('welcomeView').classList.add('hidden-view');
    document.getElementById('workspaceView').classList.remove('hidden-view');
    document.getElementById('resultBox').classList.add('hidden');
    document.getElementById('errorBox').classList.add('hidden');

    ui.set('modTitle', mod.name);
    ui.set('modDesc', mod.description);

    const input = document.getElementById('targetInput');
    input.placeholder = mod.placeholder;
    input.value = '';
    setTimeout(() => input.focus(), 60);
    renderModulesNav();
}

async function lookup() {
    const input = document.getElementById('targetInput');
    const target = input.value.trim();
    const btn = document.getElementById('searchBtn');

    if (!target || !currentModuleId) return;

    document.getElementById('errorBox').classList.add('hidden');
    document.getElementById('resultBox').classList.add('hidden');
    document.getElementById('topBar').classList.remove('opacity-100');

    btn.disabled = true;
    btn.innerHTML = `<svg class="animate-spin h-4 w-4 text-black" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>`;

    try {
        const res = await fetch(`/api/scan?module_id=${encodeURIComponent(currentModuleId)}&target=${encodeURIComponent(target)}`);
        const data = await res.json();

        if (data.status === "error") throw new Error(data.error || 'Execution failed');

        currentPayload = data.raw || data;
        const raw = currentPayload;

        document.getElementById('resultBox').classList.remove('hidden');
        document.getElementById('topBar').classList.add('opacity-100', 'pointer-events-auto');

        // Стратегия рендеринга
        const strategy = ModuleStrategies[currentModuleId] || ModuleStrategies['default'];
        strategy(raw, target);

        renderFormattedAttributes(raw);
        document.getElementById('resRaw').innerHTML = highlightJson(raw);
    } catch (e) {
        const eb = document.getElementById('errorBox');
        eb.innerText = `[!] Error: ${e.message}`;
        eb.classList.remove('hidden');
    } finally {
        btn.disabled = false;
        btn.innerText = "Execute";
    }
}

function switchView(view) {
    const isFormatted = view === 'formatted';
    document.getElementById('viewFormatted').classList.toggle('hidden', !isFormatted);
    document.getElementById('viewRaw').classList.toggle('hidden', isFormatted);

    const active = "px-3.5 py-1 text-[11px] font-mono rounded-lg bg-white text-black font-semibold shadow-md transition-all";
    const inactive = "px-3.5 py-1 text-[11px] font-mono rounded-lg text-neutral-400 hover:text-white transition-all";
    document.getElementById('tabFormatted').className = isFormatted ? active : inactive;
    document.getElementById('tabRaw').className = isFormatted ? inactive : active;
}

function copyRawJson() {
    if (!currentPayload) return;
    navigator.clipboard.writeText(JSON.stringify(currentPayload, null, 2)).then(() => {
        ui.set('copyStatus', "Copied!");
        setTimeout(() => ui.set('copyStatus', "Copy Payload JSON"), 2000);
    });
}

function highlightJson(jsonObj) {
    const jsonStr = JSON.stringify(jsonObj, null, 2).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
    return jsonStr.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, match => {
        let cls = 'text-neutral-500';
        if (/^"/.test(match)) cls = /:$/.test(match) ? 'text-white font-medium' : 'text-neutral-300';
        else if (/true|false/.test(match)) cls = 'text-neutral-400 font-bold';
        else if (/null/.test(match)) cls = 'text-neutral-700 italic';
        return `<span class="${cls}">${match}</span>`;
    });
}

window.onload = initApp;
