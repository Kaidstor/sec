import type { UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import type { MouseEvent } from "react";

const INTERACTIVE = "button, a, input, textarea, select, [role='button']";

// data-tauri-drag-region не всплывает с вложенных элементов — шапка двигает
// окно своим обработчиком, пропуская клики по интерактивным потомкам.
export function dragWindow(e: MouseEvent<HTMLElement>) {
  if (e.button !== 0) return;
  if ((e.target as HTMLElement).closest(INTERACTIVE)) return;
  e.preventDefault();
  const win = getCurrentWindow();
  void (e.detail === 2 ? win.toggleMaximize() : win.startDragging());
}

// Подписка приезжает асинхронно: отписка может случиться раньше регистрации,
// поэтому снимаем слушатель флагом, а не только через unlisten.
export function onWindowFocus(cb: () => void): () => void {
  let unlisten: UnlistenFn | undefined;
  let stopped = false;
  void getCurrentWindow()
    .onFocusChanged(({ payload: focused }) => {
      if (focused) cb();
    })
    .then((fn) => (stopped ? fn() : (unlisten = fn)));
  return () => {
    stopped = true;
    unlisten?.();
  };
}
