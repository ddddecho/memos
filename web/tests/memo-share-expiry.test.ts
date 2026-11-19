import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { describe, expect, it } from "vitest";
import { compareByExpiry, getCustomExpireDate, getDaysLeft, isShareExpired } from "@/components/MemoDetailSidebar/memoShareExpiry";
import { MemoShareSchema } from "@/types/proto/api/memo_service_pb";

const DAY_MS = 24 * 60 * 60 * 1000;
const NOW = Date.UTC(2026, 2, 10, 12);

function shareExpiringAt(ms?: number) {
  return create(MemoShareSchema, { name: "memos/a/shares/b", expireTime: ms === undefined ? undefined : timestampFromDate(new Date(ms)) });
}

describe("memoShareExpiry", () => {
  it("expires a custom date at the end of that day", () => {
    const date = getCustomExpireDate("2026-03-20");
    expect(date.getDate()).toBe(20);
    expect(date.getHours()).toBe(23);
  });

  it("counts the days left", () => {
    expect(getDaysLeft(shareExpiringAt(NOW + 3 * DAY_MS), NOW)).toBe(3);
  });

  it("treats past links as expired and keeps links without an expiry", () => {
    expect(isShareExpired(shareExpiringAt(NOW - DAY_MS), NOW)).toBe(true);
    expect(isShareExpired(shareExpiringAt(NOW + 2 * DAY_MS), NOW)).toBe(false);
    expect(isShareExpired(shareExpiringAt(), NOW)).toBe(false);
  });

  it("sorts the soonest expiry first and permanent links last", () => {
    const soon = shareExpiringAt(NOW + DAY_MS);
    const later = shareExpiringAt(NOW + 2 * DAY_MS);
    const never = shareExpiringAt();
    expect([never, later, soon].sort(compareByExpiry)).toEqual([soon, later, never]);
  });
});
