/**
 * The confirmation before `reset_settings` (round 3 of the review of #222).
 * Opened from the `settings_unverified` save notice: the reset replaces every
 * setting with its default, so it is never one click on a toast.
 */
import { RotateCcw } from 'lucide-react';
import { BirdoButton, BirdoDialog } from '@/components/birdo';
import { status, white } from '@/lib/birdo-theme';
import { resetSettings, useResetPrompt } from '@/session/settings-persist';

export const RESET_SETTINGS_BODY =
  "Your saved settings can't be verified, so changes to them can't be saved. Resetting puts " +
  'every setting back to its default, including the kill switch, your server and launch at ' +
  "login. The current file stays on disk, but BirdoVPN won't use it again.";

export function ResetSettingsDialog() {
  const open = useResetPrompt((s) => s.open);
  const close = () => useResetPrompt.setState({ open: false });
  return (
    <BirdoDialog open={open} onClose={close} title="Reset settings?" icon={RotateCcw} iconColor={status.red}>
      <p className="text-[13px]" style={{ color: white.w60 }}>
        {RESET_SETTINGS_BODY}
      </p>
      <div className="flex gap-2.5">
        <BirdoButton text="Cancel" variant="secondary" fullWidth onClick={close} />
        <BirdoButton
          text="Reset settings"
          variant="danger"
          fullWidth
          onClick={() => {
            close();
            void resetSettings();
          }}
        />
      </div>
    </BirdoDialog>
  );
}
