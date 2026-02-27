package dev.n1xend.secureauth.util;

import org.slf4j.Logger;

import java.util.ArrayList;
import java.util.List;

/**
 * Measures startup stage durations and logs a summary table.
 */
public final class StartupTimer {

    private static final long SLOW_THRESHOLD_MS = 200;
    private static final int PAD_WIDTH = 30;

    private final Logger log;
    private final List<StageTiming> stages = new ArrayList<>();
    private long currentStageStart;
    private final long overallStart = System.currentTimeMillis();

    public StartupTimer(Logger log) {
        this.log = log;
    }

    public void stage(String name) {
        currentStageStart = System.currentTimeMillis();
    }

    public void end(String name) {
        long elapsed = System.currentTimeMillis() - currentStageStart;
        stages.add(new StageTiming(name, elapsed));
    }

    public void printSummary() {
        long total = System.currentTimeMillis() - overallStart;
        log.info("[Startup] ─────────────────────────────");
        for (StageTiming s : stages) {
            String marker = s.ms() > SLOW_THRESHOLD_MS ? " <- SLOW" : "";
            log.info("[Startup] {} {}ms{}", pad(s.name()), s.ms(), marker);
        }
        log.info("[Startup] ─────────────────────────────");
        log.info("[Startup] {} {}ms", pad("TOTAL"), total);
    }

    private static String pad(String s) {
        if (s.length() >= PAD_WIDTH)
            return s;
        return s + ".".repeat(PAD_WIDTH - s.length());
    }

    private record StageTiming(String name, long ms) {
    }
}
