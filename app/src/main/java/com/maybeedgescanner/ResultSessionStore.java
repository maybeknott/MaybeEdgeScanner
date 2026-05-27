package com.maybeedgescanner;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

final class ResultSessionStore<T> {
    private final Object lock = new Object();
    private final ArrayList<T> rows = new ArrayList<>();
    private final String sessionId = UUID.randomUUID().toString();

    String sessionId() {
        return sessionId;
    }

    int append(T row) {
        synchronized (lock) {
            rows.add(row);
            return rows.size();
        }
    }

    int size() {
        synchronized (lock) {
            return rows.size();
        }
    }

    boolean isEmpty() {
        synchronized (lock) {
            return rows.isEmpty();
        }
    }

    void clear() {
        synchronized (lock) {
            rows.clear();
        }
    }

    List<T> snapshot() {
        synchronized (lock) {
            return new ArrayList<>(rows);
        }
    }
}
