import { defineBackground } from 'wxt/utils/define-background';
import { browser } from 'wxt/browser';
import { ff } from '@/lib/firefox';

/**
 * Non-persistent event page. Its only job: toolbar click toggles the sidebar.
 * All orchestration lives in the sidebar page. The listener is registered
 * synchronously so the event page can be woken by the click.
 */
export default defineBackground(() => {
  browser.action.onClicked.addListener(() => {
    // Called directly in the click handler: sidebarAction.toggle() needs the user gesture.
    void ff.sidebarAction.toggle();
  });
});
