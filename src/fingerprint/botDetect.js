/**
 * Behavioral / Bot Detection
 * Analyzes mouse movement and user interaction to detect bot-like behavior.
 */

let mouseMovements = [];
let clicks = [];
const MAX_EVENTS = 50;

// Start listeners immediately when module is imported? 
// Better to export a start/stop function to give control.

function handleMouseMove(e) {
    if (mouseMovements.length >= MAX_EVENTS) mouseMovements.shift();
    mouseMovements.push({ x: e.clientX, y: e.clientY, t: Date.now() });
}

function handleClick(e) {
    if (clicks.length >= MAX_EVENTS) clicks.shift();
    clicks.push(Date.now());
}

/**
 * Starts monitoring user behavior (mouse moves, clicks).
 */
export function startBehaviorMonitoring() {
    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('click', handleClick);
}

/**
 * Stops monitoring user behavior.
 */
export function stopBehaviorMonitoring() {
    window.removeEventListener('mousemove', handleMouseMove);
    window.removeEventListener('click', handleClick);
}

/**
 * Calculates entropy of mouse movements.
 * Low entropy indicates mechanical/straight movements.
 */
function calculateEntropy(movements) {
    if (movements.length < 5) return 0;

    // Calculate angles between consecutive moves
    const angles = [];
    for (let i = 1; i < movements.length; i++) {
        const dx = movements[i].x - movements[i - 1].x;
        const dy = movements[i].y - movements[i - 1].y;
        angles.push(Math.atan2(dy, dx));
    }

    // Bucket angles to calculate entropy
    const buckets = {};
    angles.forEach(a => {
        const bucket = Math.floor(a * 10); // Simple quantization
        buckets[bucket] = (buckets[bucket] || 0) + 1;
    });

    let entropy = 0;
    const total = angles.length;
    Object.values(buckets).forEach(count => {
        const p = count / total;
        entropy -= p * Math.log(p);
    });

    return entropy;
}

/**
 * Analyzes collected signals to detect bot likelihood.
 * @returns {{ botLikely: boolean, signals: object }}
 */
export function detectBot() {
    const entropy = calculateEntropy(mouseMovements);

    // Check for rapid clicking
    let rapidClicks = false;
    if (clicks.length > 5) {
        let shortIntervals = 0;
        for (let i = 1; i < clicks.length; i++) {
            if (clicks[i] - clicks[i - 1] < 50) shortIntervals++; // < 50ms is very fast
        }
        if (shortIntervals > 3) rapidClicks = true;
    }

    // Headless checks
    const headless =
        navigator.webdriver ||
        !navigator.languages ||
        navigator.languages.length === 0 ||
        /HeadlessChrome/.test(navigator.userAgent);

    const signals = {
        entropy,
        rapidClicks,
        headless,
        movementCount: mouseMovements.length
    };

    // Heuristic for bot detection
    const botLikely = headless || (mouseMovements.length > 10 && entropy < 0.5) || rapidClicks;

    return {
        botLikely,
        signals
    };
}
