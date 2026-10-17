/**
 * Auto-lock, driven by an injected clock so the suite does not wait out real
 * minutes. The thing worth testing is not "a timer fires" -- it is that every
 * deadline is evaluated against the clock on each tick, so a throttled or
 * suspended tab cannot stay unlocked by simply not being ticked on time.
 */

import assert from "node:assert/strict";
import { beforeEach, describe, it } from "node:test";

import { AutoLock, DEFAULT_IDLE_MS, MAX_IDLE_MS, MIN_IDLE_MS, type LockReason } from "../src/autolock.ts";

const MINUTE = 60_000;

class Clock {
  value = 1_000_000;
  now = (): number => this.value;
  advance(ms: number): void {
    this.value += ms;
  }
}

describe("AutoLock", () => {
  let clock: Clock;
  let locks: LockReason[];

  beforeEach(() => {
    clock = new Clock();
    locks = [];
  });

  const make = (overrides: Partial<ConstructorParameters<typeof AutoLock>[0]> = {}) =>
    new AutoLock({
      idleMs: 5 * MINUTE,
      now: clock.now,
      onLock: (reason) => locks.push(reason),
      ...overrides,
    });

  it("does nothing until armed", () => {
    const lock = make();
    clock.advance(MAX_IDLE_MS * 2);
    lock.tick();
    assert.deepEqual(locks, []);
  });

  it("locks once the idle window elapses", () => {
    const lock = make();
    lock.arm();

    clock.advance(5 * MINUTE - 1);
    lock.tick();
    assert.deepEqual(locks, []);

    clock.advance(1);
    lock.tick();
    assert.deepEqual(locks, ["idle"]);
  });

  it("activity pushes the deadline out", () => {
    const lock = make();
    lock.arm();

    for (let i = 0; i < 10; i++) {
      clock.advance(4 * MINUTE);
      lock.activity();
      lock.tick();
    }

    assert.deepEqual(locks, []);
  });

  it("locks only once, however many ticks follow", () => {
    const lock = make();
    lock.arm();
    clock.advance(10 * MINUTE);

    lock.tick();
    lock.tick();
    lock.tick();

    assert.deepEqual(locks, ["idle"]);
  });

  it("locks immediately when a suspended tab wakes up past the deadline", () => {
    // The realistic failure this guards against: a background tab whose timers
    // the browser throttled, so the first tick after waking is hours late.
    const lock = make();
    lock.arm();
    clock.advance(6 * 60 * MINUTE);
    lock.tick();
    assert.deepEqual(locks, ["idle"]);
  });

  describe("hidden tab", () => {
    it("locks after the grace period, well before the idle window", () => {
      const lock = make({ idleMs: 30 * MINUTE, hiddenGraceMs: MINUTE });
      lock.arm();

      lock.visibilityChanged(true);
      clock.advance(MINUTE - 1);
      lock.tick();
      assert.deepEqual(locks, []);

      clock.advance(1);
      lock.tick();
      assert.deepEqual(locks, ["hidden"]);
    });

    it("cancels the grace period when the tab comes back", () => {
      const lock = make({ idleMs: 30 * MINUTE, hiddenGraceMs: MINUTE });
      lock.arm();

      lock.visibilityChanged(true);
      clock.advance(50_000);
      lock.visibilityChanged(false);
      clock.advance(50_000);
      lock.tick();

      assert.deepEqual(locks, []);
    });

    it("does not restart the grace period on a repeated hidden event", () => {
      const lock = make({ idleMs: 30 * MINUTE, hiddenGraceMs: MINUTE });
      lock.arm();

      lock.visibilityChanged(true);
      clock.advance(40_000);
      lock.visibilityChanged(true);
      clock.advance(25_000);
      lock.tick();

      assert.deepEqual(locks, ["hidden"]);
    });
  });

  describe("session expiry", () => {
    it("locks at the token deadline even with constant activity", () => {
      const lock = make({ idleMs: 30 * MINUTE });
      lock.arm(clock.now() + 2 * MINUTE);

      clock.advance(MINUTE);
      lock.activity();
      lock.tick();
      assert.deepEqual(locks, []);

      clock.advance(MINUTE);
      lock.activity();
      lock.tick();
      assert.deepEqual(locks, ["session-expired"]);
    });

    it("reports the soonest deadline, not the first one checked", () => {
      const seen: Array<[number, LockReason]> = [];
      const lock = new AutoLock({
        idleMs: 30 * MINUTE,
        now: clock.now,
        onLock: (reason) => locks.push(reason),
        onTick: (remaining, reason) => seen.push([remaining, reason]),
      });
      lock.arm(clock.now() + MINUTE);
      lock.tick();

      assert.deepEqual(seen, [[MINUTE, "session-expired"]]);
    });
  });

  describe("manual control", () => {
    it("lockNow fires with reason 'manual'", () => {
      const lock = make();
      lock.arm();
      lock.lockNow();
      assert.deepEqual(locks, ["manual"]);
    });

    it("lockNow on an already-locked session does nothing", () => {
      const lock = make();
      lock.arm();
      lock.lockNow();
      lock.lockNow();
      assert.deepEqual(locks, ["manual"]);
    });

    it("disarm stops the timer without firing", () => {
      const lock = make();
      lock.arm();
      lock.disarm();
      clock.advance(MAX_IDLE_MS * 2);
      lock.tick();
      assert.deepEqual(locks, []);
    });

    it("re-arming after a lock starts a fresh window", () => {
      const lock = make();
      lock.arm();
      clock.advance(10 * MINUTE);
      lock.tick();
      assert.deepEqual(locks, ["idle"]);

      lock.arm();
      clock.advance(MINUTE);
      lock.tick();
      assert.deepEqual(locks, ["idle"]);
    });
  });

  describe("the idle setting", () => {
    it("clamps below the floor and above the ceiling", () => {
      const lock = make();
      lock.setIdleMs(1);
      assert.equal(lock.idleMs, MIN_IDLE_MS);

      lock.setIdleMs(MAX_IDLE_MS * 10);
      assert.equal(lock.idleMs, MAX_IDLE_MS);
    });

    it("falls back to the default for a non-finite value", () => {
      const lock = make();
      lock.setIdleMs(Number.NaN);
      assert.equal(lock.idleMs, DEFAULT_IDLE_MS);
    });

    it("a shortened window applies from the change, not retroactively", () => {
      const lock = make({ idleMs: 30 * MINUTE });
      lock.arm();
      clock.advance(20 * MINUTE);

      lock.setIdleMs(MINUTE);
      lock.tick();
      assert.deepEqual(locks, [], "shortening the window must not lock instantly");

      clock.advance(MINUTE);
      lock.tick();
      assert.deepEqual(locks, ["idle"]);
    });
  });
});
