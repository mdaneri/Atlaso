(() => {
  const panel = document.querySelector("[data-web-terminal]");
  if (!(panel instanceof HTMLElement) || panel.dataset.terminalAvailable !== "true") return;

  const fragment = new URLSearchParams(location.hash.slice(1));
  const remoteLaunch = fragment.get("remote-launch") || "";
  if (remoteLaunch) {
    history.replaceState(history.state, "", `${location.pathname}${location.search}`);
    const heading = panel.querySelector("[data-terminal-heading]");
    const description = panel.querySelector("[data-terminal-description]");
    if (heading instanceof HTMLElement) heading.textContent = "Vault Remote Terminal";
    if (description instanceof HTMLElement) {
      description.textContent = "Server-side SSH using the selected vault entry. The password is never sent to the browser.";
    }
  }

  const screen = panel.querySelector("[data-terminal-screen]");
  const status = panel.querySelector("[data-terminal-status]");
  const copyButton = panel.querySelector("[data-terminal-copy]");
  const downloadButton = panel.querySelector("[data-terminal-download]");
  const reconnectButton = panel.querySelector("[data-terminal-reconnect]");
  const errorBox = panel.querySelector("[data-terminal-error]");
  const noticeBox = panel.querySelector("[data-terminal-notice]");
  if (!(screen instanceof HTMLElement) || typeof window.Terminal !== "function") return;

  const browserSessionKey = "atlaso.webTerminal.browserSessionId";
  let browserSessionId = sessionStorage.getItem(browserSessionKey);
  if (!browserSessionId) {
    browserSessionId = crypto.randomUUID().replaceAll("-", "_");
    sessionStorage.setItem(browserSessionKey, browserSessionId);
  }

  const connectedTheme = { background: "#08131d", foreground: "#dce8f2", cursor: "#59c3ff" };
  const disconnectedTheme = { background: "#20394b", foreground: "#dce8f2", cursor: "#91a8b8" };
  const terminal = new window.Terminal({
    cols: 120,
    rows: 32,
    cursorBlink: true,
    convertEol: false,
    fontFamily: '"Cascadia Mono", "SFMono-Regular", Consolas, monospace',
    fontSize: 13,
    scrollback: 5000,
    theme: connectedTheme,
  });
  terminal.open(screen);
  let socket = null;
  let inputDisposable = null;

  const setStatus = (text, good = false) => {
    const disconnected = text === "disconnected";
    panel.classList.toggle("terminal-is-disconnected", disconnected);
    terminal.options.theme = disconnected ? disconnectedTheme : connectedTheme;
    if (!(status instanceof HTMLElement)) return;
    status.textContent = text;
    status.classList.toggle("good", good);
    status.classList.toggle("warn", !good);
  };
  const showError = (message) => {
    if (!(errorBox instanceof HTMLElement)) return;
    errorBox.textContent = message;
    errorBox.classList.remove("hidden");
  };
  const clearError = () => {
    if (errorBox instanceof HTMLElement) errorBox.classList.add("hidden");
  };
  const showNotice = (message) => {
    if (!(noticeBox instanceof HTMLElement)) return;
    noticeBox.textContent = message;
    noticeBox.classList.remove("hidden");
  };
  const clearNotice = () => {
    if (noticeBox instanceof HTMLElement) noticeBox.classList.add("hidden");
  };
  const showTransientNotice = (message) => {
    if (typeof window.showTransientGridStatus === "function") {
      window.showTransientGridStatus(message);
      return;
    }
    showNotice(message);
    window.setTimeout(clearNotice, 3000);
  };
  const setReconnectVisible = (visible) => {
    if (reconnectButton instanceof HTMLButtonElement) reconnectButton.classList.toggle("hidden", !visible);
  };
  const sessionText = () => {
    const buffer = terminal.buffer.active;
    const lines = [];
    for (let index = 0; index < buffer.length; index += 1) {
      const line = buffer.getLine(index);
      if (!line) continue;
      const text = line.translateToString(true);
      if (line.isWrapped && lines.length) lines[lines.length - 1] += text;
      else lines.push(text);
    }
    return `${lines.join("\n").trimEnd()}\n`;
  };
  const copySession = async () => {
    try {
      await navigator.clipboard.writeText(sessionText());
      clearError();
      showTransientNotice("Terminal session copied to the clipboard.");
    } catch (_error) {
      showError("The browser could not copy the terminal session to the clipboard.");
    }
  };
  const downloadSession = () => {
    const stamp = new Date().toISOString().replaceAll(":", "-");
    const url = URL.createObjectURL(new Blob([sessionText()], { type: "text/plain;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `atlaso-terminal-${stamp}.txt`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    clearError();
    showTransientNotice("Terminal session downloaded.");
  };
  const resize = () => {
    const cols = Math.max(20, Math.min(300, Math.floor(screen.clientWidth / 8.1)));
    const rows = Math.max(5, Math.min(100, Math.floor(screen.clientHeight / 17.5)));
    terminal.resize(cols, rows);
    if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: "resize", cols, rows }));
  };
  new ResizeObserver(resize).observe(screen);

  const resetSocketUi = (currentSocket) => {
    if (socket !== currentSocket) return;
    inputDisposable?.dispose();
    inputDisposable = null;
    socket = null;
    setStatus("disconnected");
    setReconnectVisible(true);
  };

  const requestTicket = async (takeover = false) => {
    const body = new FormData();
    body.set("csrf", panel.dataset.csrf || "");
    body.set("browser_session_id", browserSessionId);
    if (remoteLaunch) body.set("remote_launch", remoteLaunch);
    if (takeover) body.set("takeover", "true");
    const response = await fetch("/terminal/tickets", { method: "POST", body, headers: { "X-Requested-With": "Atlaso" } });
    let payload = null;
    try {
      payload = await response.json();
    } catch (_error) {
      payload = null;
    }
    if (response.status === 409 && payload?.error_code === "TERMINAL_SESSION_ACTIVE" && !takeover) {
      const confirmed = typeof window.requestConfirmation === "function" && await window.requestConfirmation({
        title: "Move terminal session here?",
        message: "This user already has a live terminal in another browser. Moving it here preserves the shell and terminal history, and disconnects the original browser.",
        label: "Move session here",
      });
      if (!confirmed) return null;
      return requestTicket(true);
    }
    if (!response.ok) throw new Error(payload?.detail || "Unable to create a terminal ticket.");
    return payload;
  };

  const connect = async () => {
    if (socket) return;
    clearError();
    clearNotice();
    setStatus("connecting");
    setReconnectVisible(false);
    try {
      const ticket = await requestTicket();
      if (!ticket) {
        setStatus("disconnected");
        return;
      }
      const scheme = location.protocol === "https:" ? "wss" : "ws";
      const currentSocket = new WebSocket(`${scheme}://${location.host}${ticket.websocket_path}`);
      socket = currentSocket;
      currentSocket.binaryType = "arraybuffer";
      currentSocket.addEventListener("open", () => currentSocket.send(JSON.stringify({ type: "authenticate", ticket: ticket.ticket })));
      currentSocket.addEventListener("message", (event) => {
        if (event.data instanceof ArrayBuffer) {
          terminal.write(new Uint8Array(event.data));
          return;
        }
        const message = JSON.parse(String(event.data));
        if (message.type === "ready") {
          terminal.reset();
          setStatus(`${message.resumed ? "reattached" : "connected"} as ${message.username}`, true);
          setReconnectVisible(false);
          resize();
          terminal.focus();
          inputDisposable?.dispose();
          inputDisposable = terminal.onData((data) => {
            if (currentSocket.readyState !== WebSocket.OPEN) return;
            currentSocket.send(JSON.stringify({ type: "input", data }));
          });
        } else if (message.type === "error") {
          showError(message.message || "Terminal session failed.");
        } else if (message.type === "closed") {
          setStatus(message.reason || "disconnected");
          if (message.reason === "shell exited") {
            showNotice("The shell exited through exit or Ctrl+D. Reconnect to start a new terminal shell.");
          }
        }
      });
      currentSocket.addEventListener("close", (event) => {
        if (event.code === 4410) {
          showError("This terminal session moved to another browser.");
        } else if (event.code !== 1000) {
          showError("The WebSocket connection was interrupted. Reconnect to resume the terminal session.");
        }
        resetSocketUi(currentSocket);
      });
      currentSocket.addEventListener("error", () => {
        showError("The WebSocket connection failed.");
      });
    } catch (error) {
      socket = null;
      setStatus("disconnected");
      setReconnectVisible(true);
      showError(error instanceof Error ? error.message : "Terminal connection failed.");
    }
  };
  reconnectButton?.addEventListener("click", connect);
  copyButton?.addEventListener("click", copySession);
  downloadButton?.addEventListener("click", downloadSession);
  resize();
  connect();
})();
