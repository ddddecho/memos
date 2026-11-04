import { timestampDate } from "@bufbuild/protobuf/wkt";
import type { MemoShare } from "@/types/proto/api/memo_service_pb";

const DAY_MS = 24 * 60 * 60 * 1000;

function getExpiryMs(share: MemoShare): number {
  return share.expireTime ? timestampDate(share.expireTime).getTime() : Number.POSITIVE_INFINITY;
}

/** The instant a link picked for the given date input value stops working: the end of that day. */
export function getCustomExpireDate(value: string): Date {
  const date = new Date(value);
  date.setHours(23, 59, 59, 999);
  return date;
}

/** The earliest value the custom date input accepts, as yyyy-mm-dd. */
export function getTodayInputValue(): string {
  return new Date().toISOString().slice(0, 10);
}

export function getDaysLeft(share: MemoShare, now = Date.now()): number {
  return Math.round((getExpiryMs(share) - now) / DAY_MS);
}

export function isShareExpired(share: MemoShare, now = Date.now()): boolean {
  return getDaysLeft(share, now) <= 0;
}

/** Soonest to expire first; links that never expire go last. */
export function compareByExpiry(a: MemoShare, b: MemoShare): number {
  return getExpiryMs(a) - getExpiryMs(b);
}
