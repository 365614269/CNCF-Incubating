package org.keycloak.testframework.events;

import org.jboss.logging.Logger;
import org.junit.jupiter.api.Assertions;
import org.keycloak.common.util.Time;
import org.keycloak.testframework.realm.ManagedRealm;

import java.text.SimpleDateFormat;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public abstract class AbstractEvents<R> {

    protected final ManagedRealm realm;
    protected final LinkedList<R> events = new LinkedList<>();
    protected final Set<String> processedEvents = new HashSet<>();

    protected long testStarted;
    protected long timeOffset;
    protected long lastFetch;

    protected int skip = 0;

    public AbstractEvents(ManagedRealm realm) {
        this.realm = realm;
    }

    public R poll() {
        long currentTimeOffset = getCurrentTimeOffset();
        if (timeOffset != currentTimeOffset) {
            getLogger().debugv("Timeoffset changed to {0}, resetting events", timeOffset);

            events.clear();
            timeOffset = currentTimeOffset;
            lastFetch = -1;
        }

        if (events.isEmpty()) {
            long from = lastFetch != -1 ? lastFetch : testStarted + currentTimeOffset;
            long to = getCurrentTime() + currentTimeOffset;

            Logger logger = getLogger();
            if (logger.isDebugEnabled()) {
                getLogger().debugv("Fetching events from server between {0} and {1}" + (timeOffset != 0 ? "; current timeoffset is {2}" : ""), formatDate(from), formatDate(to), timeOffset);
            }

            getEvents(from, to)
                    .stream().filter(e -> !processedEvents.contains(getEventId(e)))
                    .forEach(e -> {
                        Assertions.assertEquals(realm.getId(), getRealmId(e));
                        processedEvents.add(getEventId(e));
                        this.events.add(e);
                    });

            lastFetch = to;
        }

        while(skip > 0) {
            if (events.poll() == null) {
                return null;
            }
            skip--;
        }

        return events.poll();
    }

    public void skip() {
        skip(1);
    }

    public void skip(int events) {
        skip += events;
    }

    public void skipAll() {
        testStarted = getCurrentTime();
    }

    public void clear() {
        events.clear();
        clearServerEvents();
    }

    void testStarted() {
        testStarted = getCurrentTime();
        timeOffset = getCurrentTimeOffset();
        lastFetch = -1;
    }

    protected abstract List<R> getEvents(long from, long to);

    protected abstract String getEventId(R representation);

    protected abstract String getRealmId(R representation);

    protected abstract void clearServerEvents();

    protected abstract Logger getLogger();

    protected long getCurrentTime() {
        return System.currentTimeMillis();
    }

    protected long getCurrentTimeOffset() {
        return TimeUnit.MILLISECONDS.convert(Time.getOffset(), TimeUnit.SECONDS);
    }

    protected String formatDate(long timestamp) {
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss,SSS").format(timestamp);
    }

}
