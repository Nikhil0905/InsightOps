/* ============================================
   InsightOps — Interactive JavaScript
   ============================================ */

document.addEventListener('DOMContentLoaded', () => {
    initNavbar();
    initMobileNav();
    initTypingEffect();
    initTerminal();
    initDetections();
    initScrollAnimations();
    initCountUp();
    initWeightBars();
    initCopyButtons();
    initParticles();
});

/* --- Navbar Scroll Effect --- */
function initNavbar() {
    const navbar = document.getElementById('navbar');
    let lastScroll = 0;

    window.addEventListener('scroll', () => {
        const currentScroll = window.scrollY;
        if (currentScroll > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
        lastScroll = currentScroll;
    });

    // Active link highlight
    const sections = document.querySelectorAll('section[id]');
    const navLinks = document.querySelectorAll('.nav-links a[href^="#"]');

    window.addEventListener('scroll', () => {
        let current = '';
        sections.forEach(section => {
            const sectionTop = section.offsetTop - 100;
            if (window.scrollY >= sectionTop) {
                current = section.getAttribute('id');
            }
        });
        navLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === `#${current}`) {
                link.classList.add('active');
            }
        });
    });
}

/* --- Mobile Navigation --- */
function initMobileNav() {
    const toggle = document.getElementById('navToggle');
    const links = document.getElementById('navLinks');

    toggle.addEventListener('click', () => {
        links.classList.toggle('active');
        toggle.classList.toggle('active');
    });

    links.querySelectorAll('a').forEach(link => {
        link.addEventListener('click', () => {
            links.classList.remove('active');
            toggle.classList.remove('active');
        });
    });
}

/* --- Typing Effect --- */
function initTypingEffect() {
    const phrases = [
        'correlates security alerts',
        'maps MITRE ATT&CK techniques',
        'scores risk deterministically',
        'generates analyst-ready narratives',
        'protects decision integrity'
    ];

    const el = document.getElementById('typedText');
    if (!el) return;

    let phraseIdx = 0;
    let charIdx = 0;
    let isDeleting = false;
    let speed = 60;

    function type() {
        const currentPhrase = phrases[phraseIdx];

        if (isDeleting) {
            el.textContent = currentPhrase.substring(0, charIdx - 1);
            charIdx--;
            speed = 30;
        } else {
            el.textContent = currentPhrase.substring(0, charIdx + 1);
            charIdx++;
            speed = 60;
        }

        if (!isDeleting && charIdx === currentPhrase.length) {
            isDeleting = true;
            speed = 2000; // Pause at end
        } else if (isDeleting && charIdx === 0) {
            isDeleting = false;
            phraseIdx = (phraseIdx + 1) % phrases.length;
            speed = 300;
        }

        setTimeout(type, speed);
    }

    setTimeout(type, 1000);
}

/* --- Terminal Animation (fallback when server not running) --- */
let _backendAvailable = false;
let _currentEventSource = null;
let _terminalHasLiveOutput = false;

function initTerminal() {
    const output = document.getElementById('terminalOutput');
    if (!output) return;

    // Check if Flask backend is available
    fetch('/api/status', { method: 'GET' })
        .then(r => r.json())
        .then(data => {
            _backendAvailable = true;
            setTerminalStatus('idle', 'Ready');
            // Show welcome message
            appendTerminalLine('$ InsightOps web server connected', 'line-system success');
            appendTerminalLine(`  Engine: ${data.engine_exists ? '✓' : '✗'} ai-engine/main.py`, data.engine_exists ? 't-green' : 't-red');
            appendTerminalLine(`  Tests:  ${data.tests_exist ? '✓' : '✗'} tests/`, data.tests_exist ? 't-green' : 't-red');
            appendTerminalLine('', '');
            appendTerminalLine('Click a button above to run the pipeline or tests live.', 't-dim');
        })
        .catch(() => {
            _backendAvailable = false;
            // No server — run the animated simulation as fallback
            runTerminalAnimation(output);
        });
}

function runTerminalAnimation(output) {
    const lines = [
        { text: '$ python ai-engine/main.py --dry-run', cls: 't-bold', delay: 0 },
        { text: '', delay: 400 },
        { text: 'INFO  Dry run enabled: no data will be sent to Splunk', cls: 't-cyan', delay: 600 },
        { text: '', delay: 100 },
        { text: '--- Signal Health Check ---', cls: 't-bold', delay: 800 },
        { text: '[OK] linux_secure: last event 2 minutes ago', cls: 't-green', delay: 400 },
        { text: '⚠️  wineventlog:security: no events in last 12 minutes', cls: 't-yellow', delay: 400 },
        { text: '[OK] alert:InsightOps*: last event 1 minute ago', cls: 't-green', delay: 400 },
        { text: '---------------------------', cls: 't-dim', delay: 300 },
        { text: '', delay: 200 },
        { text: 'INFO  Fetching alerts from Splunk (index=main)', cls: 't-cyan', delay: 600 },
        { text: 'INFO  Classified 4 alerts (2 HIGH, 1 CRITICAL, 1 LOW)', cls: 't-cyan', delay: 500 },
        { text: 'INFO  Scored 4 alerts', cls: 't-cyan', delay: 400 },
        { text: '', delay: 200 },
        { text: 'INFO  Correlated 2 incidents', cls: 't-cyan', delay: 500 },
        { text: '  → Incident af3c89d1: risk=87.5 (3 alerts, CRITICAL)', cls: 't-red', delay: 300 },
        { text: '    ├─ T1110.003  Password Spraying', cls: 't-dim', delay: 200 },
        { text: '    ├─ T1558.003  Kerberoasting', cls: 't-dim', delay: 200 },
        { text: '    └─ T1068      Privilege Escalation', cls: 't-dim', delay: 200 },
        { text: '  → Incident b7e21a4f: risk=42.0 (1 alert, HIGH)', cls: 't-yellow', delay: 300 },
        { text: '    └─ T1110.001  SSH Brute Force', cls: 't-dim', delay: 200 },
        { text: '', delay: 200 },
        { text: 'INFO  [DRY-RUN] Would write incident af3c89d1 to Splunk HEC', cls: 't-green', delay: 400 },
        { text: 'INFO  [DRY-RUN] Would write incident b7e21a4f to Splunk HEC', cls: 't-green', delay: 400 },
        { text: '', delay: 200 },
        { text: '✓ Pipeline complete — 2 incidents processed in 1.3s', cls: 't-green', delay: 500 }
    ];

    let i = 0;

    function addLine() {
        if (_terminalHasLiveOutput) return; // Stop if user started live session
        if (i >= lines.length) {
            setTimeout(() => {
                if (_terminalHasLiveOutput) return;
                output.innerHTML = '';
                i = 0;
                addLine();
            }, 4000);
            return;
        }

        const line = lines[i];
        const span = document.createElement('span');
        span.className = line.cls || '';
        span.textContent = line.text;
        output.appendChild(span);
        output.appendChild(document.createTextNode('\n'));

        const body = document.getElementById('terminalBody');
        if (body) body.scrollTop = body.scrollHeight;

        i++;
        setTimeout(addLine, lines[i - 1].delay || 200);
    }

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                setTimeout(addLine, 800);
                observer.disconnect();
            }
        });
    }, { threshold: 0.3 });

    const hero = document.getElementById('hero');
    if (hero) observer.observe(hero);
}

/* --- Live Terminal Functions --- */

function appendTerminalLine(text, className) {
    const output = document.getElementById('terminalOutput');
    if (!output) return;

    const span = document.createElement('span');
    if (className) span.className = className;
    span.textContent = text;
    output.appendChild(span);
    output.appendChild(document.createTextNode('\n'));

    const body = document.getElementById('terminalBody');
    if (body) body.scrollTop = body.scrollHeight;
}

function setTerminalStatus(state, text) {
    const statusDot = document.querySelector('.status-dot');
    const statusText = document.querySelector('.status-text');
    if (statusDot) {
        statusDot.className = 'status-dot ' + state;
    }
    if (statusText) {
        statusText.textContent = text;
    }
}

function setButtonsDisabled(disabled) {
    document.querySelectorAll('.run-btn').forEach(btn => {
        if (!btn.classList.contains('run-clear')) {
            btn.disabled = disabled;
        }
    });
}

function runPipeline(mode) {
    if (!_backendAvailable) {
        alert('Flask server is not running. Start it with:\n\npython web/server.py');
        return;
    }

    if (_currentEventSource) {
        _currentEventSource.close();
    }

    _terminalHasLiveOutput = true;
    const output = document.getElementById('terminalOutput');
    output.innerHTML = '';

    const title = document.getElementById('terminalTitle');
    if (title) title.textContent = mode === 'dry-run' ? 'insightops — dry-run' : 'insightops — full pipeline';

    const cmd = mode === 'dry-run'
        ? '$ python ai-engine/main.py --dry-run'
        : '$ python ai-engine/main.py';
    appendTerminalLine(cmd, 't-bold');
    appendTerminalLine('', '');

    setTerminalStatus('running', 'Running...');
    setButtonsDisabled(true);

    const url = `/api/run-pipeline?mode=${mode}`;
    _currentEventSource = new EventSource(url);

    _currentEventSource.onmessage = function (event) {
        try {
            const data = JSON.parse(event.data);

            if (data.done) {
                _currentEventSource.close();
                _currentEventSource = null;
                setButtonsDisabled(false);

                if (data.exit_code === 0) {
                    setTerminalStatus('success', 'Complete');
                    appendTerminalLine('', '');
                    appendTerminalLine('✓ Pipeline finished successfully', 'line-system success');
                } else {
                    setTerminalStatus('error', `Exit ${data.exit_code}`);
                    appendTerminalLine('', '');
                    appendTerminalLine(`✗ Pipeline exited with code ${data.exit_code}`, 'line-system error');
                }
                return;
            }

            // Color-code output lines
            let cls = '';
            if (data.stream === 'stderr') {
                if (data.line.startsWith('INFO')) cls = 't-cyan';
                else if (data.line.startsWith('WARNING')) cls = 't-yellow';
                else if (data.line.startsWith('ERROR')) cls = 't-red';
                else cls = 'line-stderr';
            } else {
                // stdout — JSON output from dry-run
                if (data.line.startsWith('{') || data.line.startsWith('}') || data.line.startsWith('  "')) {
                    cls = 't-dim';
                } else if (data.line === '---') {
                    cls = 't-dim';
                }
            }

            appendTerminalLine(data.line, cls);
        } catch (e) {
            appendTerminalLine(event.data, '');
        }
    };

    _currentEventSource.onerror = function () {
        _currentEventSource.close();
        _currentEventSource = null;
        setTerminalStatus('error', 'Disconnected');
        setButtonsDisabled(false);
        appendTerminalLine('', '');
        appendTerminalLine('✗ Connection lost to server', 'line-system error');
    };
}

function runTests() {
    if (!_backendAvailable) {
        alert('Flask server is not running. Start it with:\n\npython web/server.py');
        return;
    }

    if (_currentEventSource) {
        _currentEventSource.close();
    }

    _terminalHasLiveOutput = true;
    const output = document.getElementById('terminalOutput');
    output.innerHTML = '';

    const title = document.getElementById('terminalTitle');
    if (title) title.textContent = 'insightops — pytest';

    appendTerminalLine('$ pytest tests/ -v', 't-bold');
    appendTerminalLine('', '');

    setTerminalStatus('running', 'Testing...');
    setButtonsDisabled(true);

    _currentEventSource = new EventSource('/api/run-tests');

    _currentEventSource.onmessage = function (event) {
        try {
            const data = JSON.parse(event.data);

            if (data.done) {
                _currentEventSource.close();
                _currentEventSource = null;
                setButtonsDisabled(false);

                if (data.exit_code === 0) {
                    setTerminalStatus('success', 'All Passed');
                    appendTerminalLine('', '');
                    appendTerminalLine('✓ All tests passed!', 'line-system success');
                } else {
                    setTerminalStatus('error', 'Failed');
                    appendTerminalLine('', '');
                    appendTerminalLine(`✗ Tests failed (exit code ${data.exit_code})`, 'line-system error');
                }
                return;
            }

            let cls = '';
            if (data.line.includes('PASSED')) cls = 't-green';
            else if (data.line.includes('FAILED')) cls = 't-red';
            else if (data.line.includes('ERROR')) cls = 't-red';
            else if (data.line.includes('warnings summary') || data.line.startsWith('=')) cls = 't-dim';
            else if (data.stream === 'stderr') cls = 'line-stderr';

            appendTerminalLine(data.line, cls);
        } catch (e) {
            appendTerminalLine(event.data, '');
        }
    };

    _currentEventSource.onerror = function () {
        _currentEventSource.close();
        _currentEventSource = null;
        setTerminalStatus('error', 'Disconnected');
        setButtonsDisabled(false);
        appendTerminalLine('', '');
        appendTerminalLine('✗ Connection lost to server', 'line-system error');
    };
}

function clearTerminal() {
    if (_currentEventSource) {
        _currentEventSource.close();
        _currentEventSource = null;
    }

    const output = document.getElementById('terminalOutput');
    if (output) output.innerHTML = '';

    const title = document.getElementById('terminalTitle');
    if (title) title.textContent = 'insightops';

    setTerminalStatus('idle', _backendAvailable ? 'Ready' : 'Idle');
    setButtonsDisabled(false);
}

/* --- Detection Cards --- */
function initDetections() {
    const detections = [
        { name: 'Password Spraying', platform: 'Windows / Linux', mitre: 'T1110.003', severity: 'HIGH', tags: ['windows', 'linux'] },
        { name: 'SSH Brute Force', platform: 'Linux', mitre: 'T1110.001', severity: 'LOW', tags: ['linux'] },
        { name: 'Kerberoasting', platform: 'Windows', mitre: 'T1558.003', severity: 'CRITICAL', tags: ['windows'] },
        { name: 'Lateral Movement', platform: 'Windows', mitre: 'T1021', severity: 'HIGH', tags: ['windows'] },
        { name: 'Lateral Movement (SSH)', platform: 'Linux', mitre: 'T1021.004', severity: 'HIGH', tags: ['linux'] },
        { name: 'Privilege Escalation', platform: 'Windows', mitre: 'T1068', severity: 'CRITICAL', tags: ['windows'] },
        { name: 'Privilege Escalation (sudo/SUID)', platform: 'Linux', mitre: 'T1548.003', severity: 'CRITICAL', tags: ['linux'] },
        { name: 'Persistence', platform: 'Windows', mitre: 'T1547', severity: 'CRITICAL', tags: ['windows'] },
        { name: 'Persistence (cron)', platform: 'Linux', mitre: 'T1053.003', severity: 'CRITICAL', tags: ['linux'] },
        { name: 'Credential Dumping', platform: 'Windows / Linux', mitre: 'T1003', severity: 'CRITICAL', tags: ['windows', 'linux'] },
        { name: 'Ransomware Pre-Impact', platform: 'Windows / Linux', mitre: 'T1490', severity: 'CRITICAL', tags: ['windows', 'linux'] }
    ];

    const grid = document.getElementById('detectionGrid');
    if (!grid) return;

    function renderCards(filter) {
        grid.innerHTML = '';

        const filtered = filter === 'all'
            ? detections
            : filter === 'critical'
                ? detections.filter(d => d.severity === 'CRITICAL')
                : detections.filter(d => d.tags.includes(filter));

        filtered.forEach((d, idx) => {
            const card = document.createElement('div');
            card.className = 'detection-card';
            card.setAttribute('data-severity', d.severity);
            card.style.animationDelay = `${idx * 50}ms`;
            card.style.animation = 'fadeInUp 0.4s ease forwards';
            card.style.opacity = '0';

            const severityClass = d.severity.toLowerCase();
            const platformIcon = d.platform.includes('Windows') && d.platform.includes('Linux')
                ? '🖥️ 🐧'
                : d.platform.includes('Windows') ? '🖥️' : '🐧';

            card.innerHTML = `
                <div class="d-header">
                    <span class="d-name">${d.name}</span>
                    <span class="d-severity ${severityClass}">${d.severity}</span>
                </div>
                <div class="d-meta">
                    <span class="d-platform">${platformIcon} ${d.platform}</span>
                    <span class="d-mitre">${d.mitre}</span>
                </div>
            `;

            grid.appendChild(card);
        });
    }

    renderCards('all');

    // Filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            renderCards(btn.dataset.filter);
        });
    });
}

/* --- Scroll Animations --- */
function initScrollAnimations() {
    const elements = document.querySelectorAll('[data-aos]');

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const delay = entry.target.getAttribute('data-aos-delay') || 0;
                setTimeout(() => {
                    entry.target.classList.add('visible');
                }, parseInt(delay));
            }
        });
    }, {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    });

    elements.forEach(el => observer.observe(el));
}

/* --- Count-Up Animation --- */
function initCountUp() {
    const statValues = document.querySelectorAll('.stat-value[data-count]');

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const el = entry.target;
                const target = parseInt(el.dataset.count);
                let current = 0;
                const increment = target / 40;
                const timer = setInterval(() => {
                    current += increment;
                    if (current >= target) {
                        el.textContent = target;
                        clearInterval(timer);
                    } else {
                        el.textContent = Math.floor(current);
                    }
                }, 30);
                observer.unobserve(el);
            }
        });
    }, { threshold: 0.5 });

    statValues.forEach(el => observer.observe(el));
}

/* --- Weight Bars Animation --- */
function initWeightBars() {
    const fills = document.querySelectorAll('.weight-fill');

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const el = entry.target;
                const width = el.dataset.width || 0;
                setTimeout(() => {
                    el.style.width = width + '%';
                }, 300);
                observer.unobserve(el);
            }
        });
    }, { threshold: 0.3 });

    fills.forEach(el => observer.observe(el));
}

/* --- Copy Buttons --- */
function initCopyButtons() {
    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const text = btn.dataset.copy;
            navigator.clipboard.writeText(text).then(() => {
                const original = btn.textContent;
                btn.textContent = 'Copied!';
                btn.style.background = 'var(--green)';
                btn.style.borderColor = 'var(--green)';
                btn.style.color = 'var(--bg-primary)';
                setTimeout(() => {
                    btn.textContent = original;
                    btn.style.background = '';
                    btn.style.borderColor = '';
                    btn.style.color = '';
                }, 1500);
            });
        });
    });
}

/* --- Floating Particles --- */
function initParticles() {
    const container = document.getElementById('particles');
    if (!container) return;

    const count = 30;

    for (let i = 0; i < count; i++) {
        const particle = document.createElement('div');
        const size = Math.random() * 3 + 1;
        const x = Math.random() * 100;
        const y = Math.random() * 100;
        const duration = Math.random() * 20 + 10;
        const delay = Math.random() * 10;
        const opacity = Math.random() * 0.4 + 0.1;

        particle.style.cssText = `
            position: absolute;
            width: ${size}px;
            height: ${size}px;
            background: var(--accent);
            border-radius: 50%;
            left: ${x}%;
            top: ${y}%;
            opacity: ${opacity};
            animation: float-particle ${duration}s ease-in-out ${delay}s infinite alternate;
            pointer-events: none;
        `;

        container.appendChild(particle);
    }

    // Add floating animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes float-particle {
            0% { transform: translate(0, 0) scale(1); opacity: 0.1; }
            50% { opacity: 0.4; }
            100% { transform: translate(${Math.random() > 0.5 ? '' : '-'}${Math.random() * 60 + 20}px, ${Math.random() > 0.5 ? '' : '-'}${Math.random() * 60 + 20}px) scale(1.5); opacity: 0.1; }
        }
    `;
    document.head.appendChild(style);
}

/* --- Smooth Scroll for Anchor Links --- */
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    });
});
