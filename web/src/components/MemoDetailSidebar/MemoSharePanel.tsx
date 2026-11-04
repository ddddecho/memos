import { timestampDate } from "@bufbuild/protobuf/wkt";
import { ConnectError } from "@connectrpc/connect";
import { CheckIcon, CopyIcon, LinkIcon, Loader2Icon, Trash2Icon } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "react-hot-toast";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { getShareUrl, useCreateMemoShare, useDeleteMemoShare, useMemoShares } from "@/hooks/useMemoShareQueries";
import type { MemoShare } from "@/types/proto/api/memo_service_pb";
import { useTranslate } from "@/utils/i18n";
import { compareByExpiry, getCustomExpireDate, getDaysLeft, getTodayInputValue, isShareExpired } from "./memoShareExpiry";

type ExpiryOption = "never" | "1d" | "7d" | "30d" | "custom";

function getExpireDate(option: ExpiryOption, customDate: string): Date | undefined {
  if (option === "never") return undefined;
  if (option === "custom") return getCustomExpireDate(customDate);
  const d = new Date();
  if (option === "1d") d.setDate(d.getDate() + 1);
  else if (option === "7d") d.setDate(d.getDate() + 7);
  else if (option === "30d") d.setDate(d.getDate() + 30);
  return d;
}

function formatExpiry(share: MemoShare, t: ReturnType<typeof useTranslate>): string {
  if (!share.expireTime) return t("memo.share.never-expires");
  if (isShareExpired(share)) return t("memo.share.expired");
  const daysLeft = getDaysLeft(share);
  if (daysLeft <= 7) return t("memo.share.expires-in-days", { count: daysLeft });
  const d = timestampDate(share.expireTime);
  return t("memo.share.expires-on", { date: d.toLocaleDateString() });
}

interface ShareLinkRowProps {
  share: MemoShare;
  memoName: string;
}

function ShareLinkRow({ share, memoName }: ShareLinkRowProps) {
  const t = useTranslate();
  const [copied, setCopied] = useState(false);
  const deleteShare = useDeleteMemoShare();
  const url = getShareUrl(share);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleRevoke = async () => {
    try {
      await deleteShare.mutateAsync({ name: share.name, memoName });
      toast.success(t("memo.share.revoked"));
    } catch (e) {
      toast.error((e as ConnectError).message || t("memo.share.revoke-failed"));
    }
  };

  return (
    <div className="flex flex-col gap-1 rounded-md border border-border p-3">
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-mono text-xs text-muted-foreground">{url}</span>
        <div className="flex shrink-0 items-center gap-1">
          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={handleCopy} title={t("memo.share.copy")}>
            {copied ? <CheckIcon className="h-3.5 w-3.5 text-success" /> : <CopyIcon className="h-3.5 w-3.5" />}
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-destructive hover:text-destructive"
            onClick={handleRevoke}
            disabled={deleteShare.isPending}
            title={t("memo.share.revoke")}
          >
            <Trash2Icon className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>
      <p className="text-xs text-muted-foreground">{formatExpiry(share, t)}</p>
    </div>
  );
}

interface MemoSharePanelProps {
  open: boolean;
  onClose: () => void;
  memoName: string;
}

const MemoSharePanel = ({ open, onClose, memoName }: MemoSharePanelProps) => {
  const t = useTranslate();
  const [expiry, setExpiry] = useState<ExpiryOption>("never");
  const [customDate, setCustomDate] = useState("");
  const { data: shares = [], isLoading } = useMemoShares(memoName, { enabled: open });
  const createShare = useCreateMemoShare();
  const deleteShare = useDeleteMemoShare();
  const sortedShares = shares.sort(compareByExpiry);
  const expiredShares = sortedShares.filter((share) => isShareExpired(share));

  const expiryOptions = useMemo(
    () => [
      { value: "never", label: t("memo.share.expiry-never") },
      { value: "1d", label: t("memo.share.expiry-1-day") },
      { value: "7d", label: t("memo.share.expiry-7-days") },
      { value: "30d", label: t("memo.share.expiry-30-days") },
      { value: "custom", label: t("memo.share.expiry-custom") },
    ],
    [t],
  );

  const handleCreate = async () => {
    try {
      await createShare.mutateAsync({ memoName, expireTime: getExpireDate(expiry, customDate) });
    } catch (e) {
      toast.error((e as ConnectError).message || t("memo.share.create-failed"));
    }
  };

  const handleRemoveExpired = async () => {
    try {
      await Promise.all(expiredShares.map((share) => deleteShare.mutateAsync({ name: share.name, memoName })));
      toast.success(t("memo.share.revoked"));
    } catch (e) {
      toast.error((e as ConnectError).message || t("memo.share.revoke-failed"));
    }
  };

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <LinkIcon className="h-4 w-4" />
            {t("memo.share.title")}
          </DialogTitle>
        </DialogHeader>

        <div className="flex flex-col gap-4 py-2">
          {/* Active links */}
          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between gap-2">
              <p className="text-sm font-medium text-muted-foreground">{t("memo.share.active-links")}</p>
              {expiredShares.length > 0 && (
                <Button variant="ghost" size="sm" onClick={handleRemoveExpired} disabled={deleteShare.isPending}>
                  {t("memo.share.remove-expired")}
                </Button>
              )}
            </div>
            {isLoading ? (
              <Loader2Icon className="h-4 w-4 animate-spin text-muted-foreground" />
            ) : shares.length === 0 ? (
              <p className="text-sm text-muted-foreground">{t("memo.share.no-links")}</p>
            ) : (
              <div className="flex flex-col gap-2">
                {sortedShares.map((share) => (
                  <ShareLinkRow key={share.name} share={share} memoName={memoName} />
                ))}
              </div>
            )}
          </div>

          {/* Create new link */}
          <div className="flex items-center gap-2">
            <Select value={expiry} items={expiryOptions} onValueChange={(v) => setExpiry(v as ExpiryOption)}>
              <SelectTrigger className="w-36">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {expiryOptions.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {expiry === "custom" && (
              <Input
                type="date"
                className="w-40"
                min={getTodayInputValue()}
                value={customDate}
                onChange={(e) => setCustomDate(e.target.value)}
                aria-label={t("memo.share.expiry-custom")}
              />
            )}
            <Button onClick={handleCreate} disabled={createShare.isPending} className="flex-1">
              {createShare.isPending ? (
                <>
                  <Loader2Icon className="mr-2 h-4 w-4 animate-spin" />
                  {t("memo.share.creating")}
                </>
              ) : (
                t("memo.share.create-link")
              )}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default MemoSharePanel;
