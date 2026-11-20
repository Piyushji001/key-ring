import { useState, useEffect, useRef, useCallback } from "react";
import {
  Sparkles,
  Send,
  X,
  RotateCcw,
  Terminal,
  Shield,
  Check,
  Copy,
  AlertCircle,
  Server,
  RefreshCw,
  ArrowRight,
} from "lucide-react";
import clsx from "clsx";

import { ipc, asAppError } from "../lib/ipc";
import type { RecordTypeInfo } from "../lib/types";
import { Button, Kbd } from "./ui";

export interface ParsedConnection {
  type: "ssh" | "cloud" | "database" | "login";
  title: string;
  host?: string;
  port?: string;
  username?: string;
  password?: string;
  authMethod?: "password" | "key";
  provider?: "aws" | "gcp" | "azure" | "kubernetes";
  fields: Record<string, string>;
  tags: string[];
}

export interface CopilotActionCard {
  title: string;
  subtitle?: string;
  fields: Record<string, string>;
  recordType: string;
  tags: string[];
  primaryLabel: string;
  onPrimary: () => Promise<void>;
  secondaryLabel?: string;
  onSecondary?: () => Promise<void>;
  editLabel?: string;
  onEdit?: () => void;
}

export interface CopilotMessage {
  id: string;
  sender: "user" | "copilot";
  timestamp: number;
  text: string;
  badge?: string;
  actionCard?: CopilotActionCard;
  codeSnippet?: { language: string; code: string; title?: string };
  troubleshooting?: {
    cause: string;
    steps: string[];
    fixCommand?: string;
  };
  outOfScope?: {
    limitation: string;
    why: string;
    nextSteps: string[];
    externalAction?: string;
  };
  chips?: { label: string; query: string }[];
}

interface WizardState {
  mode: "idle" | "ssh" | "cloud";
  step: number;
  data: Record<string, string>;
}

export function CopilotDrawer({
  isOpen,
  onClose,
  types: _types,
  onOpenNewRecord,
  onOpenSettings,
  onSearch,
  onRecordCreated,
}: {
  isOpen: boolean;
  onClose: () => void;
  types?: RecordTypeInfo[];
  onOpenNewRecord: (
    initialType?: string | null,
    initialValues?: Record<string, string>,
    initialTitle?: string,
  ) => void;
  onOpenSettings: () => void;
  onSearch: (query: string) => void;
  onRecordCreated: (id: string) => void;
}) {
  const [messages, setMessages] = useState<CopilotMessage[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [wizard, setWizard] = useState<WizardState>({
    mode: "idle",
    step: 0,
    data: {},
  });

  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Initialize with helpful welcome message
  useEffect(() => {
    if (messages.length === 0) {
      setMessages([
        {
          id: "welcome",
          sender: "copilot",
          timestamp: Date.now(),
          text: `**Welcome to Keyring Copilot** ✦\n\nI am your **100% offline** assistant. Because Keyring operates in a zero-network sandbox, your credentials never leave your machine.\n\nHere is how I can assist you right now:`,
          chips: [
            { label: "🚀 Connect to an SSH server", query: "I want to connect to a server" },
            { label: "☁️ Add AWS / Cloud credentials", query: "Setup AWS credentials" },
            { label: "❓ Fix SSH 'Wrong Password'", query: "Why is SSH saying wrong password?" },
            { label: "🔑 Generate a strong password", query: "Generate a strong password" },
            { label: "🛡️ How is my vault encrypted?", query: "How does Keyring encryption work?" },
            { label: "💾 Create a backup now", query: "Create backup now" },
          ],
        },
      ]);
    }
  }, [messages.length]);

  // Scroll to bottom when new messages arrive
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => {
        scrollRef.current?.scrollTo({
          top: scrollRef.current.scrollHeight,
          behavior: "smooth",
        });
        inputRef.current?.focus();
      }, 50);
    }
  }, [isOpen, messages]);

  const copyToClipboard = useCallback((text: string, id: string) => {
    void navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  }, []);

  const resetChat = () => {
    setWizard({ mode: "idle", step: 0, data: {} });
    setMessages([
      {
        id: "reset-" + Date.now(),
        sender: "copilot",
        timestamp: Date.now(),
        text: `Chat reset. What would you like help with?`,
        chips: [
          { label: "🚀 Connect to SSH", query: "I want to connect to a server" },
          { label: "☁️ Add Cloud Account", query: "Setup Cloud credentials" },
          { label: "❓ SSH Troubleshooting", query: "SSH troubleshooting" },
          { label: "🛡️ Security Architecture", query: "Vault security architecture" },
        ],
      },
    ]);
  };

  /**
   * Smart Parser: Attempts to extract credentials from raw connection strings or natural language.
   * e.g. "ssh root@94.136.186.9 pass: s5i8U2jO7"
   * e.g. "ssh -p 2222 admin@myserver.com password=secret"
   */
  const parseRawCredentials = (raw: string): ParsedConnection | null => {
    const text = raw.trim();

    // 1. SSH pattern matching
    const sshCmdMatch = text.match(
      /(?:ssh\s+)?(?:-p\s*(\d+)\s+)?(?:([a-zA-Z0-9_\-\.]+)@)?([a-zA-Z0-9_\-\.]+)(?::(\d+))?(?:[\s,]+(?:pass|password|pwd)[:=\s]+(\S+))?/i,
    );

    const hasSshSignals =
      text.toLowerCase().startsWith("ssh ") ||
      text.includes("@") ||
      text.toLowerCase().includes("pass:") ||
      text.toLowerCase().includes("password:");

    if (hasSshSignals && sshCmdMatch) {
      const port = sshCmdMatch[1] || sshCmdMatch[4] || "22";
      const username = sshCmdMatch[2] || "root";
      const host = sshCmdMatch[3] || "";
      let password = sshCmdMatch[5] || "";

      // Try extra password extract if formatted as "pass: xyz" on next line
      if (!password) {
        const passMatch = text.match(/(?:pass|password|pwd)[:=\s]+(\S+)/i);
        if (passMatch) password = passMatch[1] ?? "";
      }

      if (host && host.includes(".") && !host.includes("http")) {
        const fields: Record<string, string> = {
          host,
          port,
          username,
          auth_method: password ? "password" : "key",
        };
        if (password) fields.password = password;

        return {
          type: "ssh",
          title: `SSH - ${host}`,
          host,
          port,
          username,
          password,
          authMethod: password ? "password" : "key",
          fields,
          tags: ["SSH", "Server", "Remote"],
        };
      }
    }

    // 2. AWS Credentials pattern matching
    const hasAwsKey = /(?:AKIA[0-9A-Z]{16})/i.test(text) || text.toLowerCase().includes("aws");
    if (hasAwsKey) {
      const keyMatch = text.match(/AKIA[0-9A-Z]{16}/);
      const secretMatch = text.match(/(?:secret[_\-\s]*key[:=\s]+)?([a-zA-Z0-9/+=]{40})/i);
      const regionMatch = text.match(/(?:region[:=\s]+)?([a-z]{2}-[a-z]+-\d)/i);

      if (keyMatch || secretMatch) {
        const fields: Record<string, string> = {
          provider: "aws",
          access_key_id: keyMatch ? keyMatch[0] : "",
          secret_access_key: secretMatch ? (secretMatch[1] ?? "") : "",
          default_region: regionMatch ? (regionMatch[1] ?? "us-east-1") : "us-east-1",
        };
        return {
          type: "cloud",
          title: `AWS Account (${fields.default_region})`,
          provider: "aws",
          fields,
          tags: ["AWS", "Cloud", "CLI"],
        };
      }
    }

    return null;
  };

  /**
   * Main query processor: handles wizards, direct actions, offline knowledge base, and out-of-scope replies.
   */
  const handleUserMessage = async (queryText: string) => {
    const q = queryText.trim();
    if (!q) return;

    // Add user message
    const userMsg: CopilotMessage = {
      id: "u-" + Date.now(),
      sender: "user",
      timestamp: Date.now(),
      text: q,
    };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setBusy(true);

    const lower = q.toLowerCase();

    // -------------------------------------------------------------
    // WIZARD IN PROGRESS
    // -------------------------------------------------------------
    if (wizard.mode === "ssh") {
      if (lower === "cancel" || lower === "exit" || lower === "stop") {
        setWizard({ mode: "idle", step: 0, data: {} });
        setMessages((prev) => [
          ...prev,
          {
            id: "wiz-cancel-" + Date.now(),
            sender: "copilot",
            timestamp: Date.now(),
            text: "Wizard cancelled. What else can I assist you with?",
          },
        ]);
        setBusy(false);
        return;
      }

      const step = wizard.step;
      const data = { ...wizard.data };

      if (step === 1) {
        // Step 1: Host
        let host = q.trim();
        let username = "root";
        let port = "22";

        if (host.includes("@")) {
          const parts = host.split("@");
          username = parts[0]?.trim() || "root";
          host = parts[1]?.trim() || "";
        }
        if (host.includes(":")) {
          const parts = host.split(":");
          host = parts[0]?.trim() || "";
          port = parts[1]?.trim() || "22";
        }

        data.host = host;
        data.username = username;
        data.port = port;

        setWizard({ mode: "ssh", step: 2, data });
        setMessages((prev) => [
          ...prev,
          {
            id: "ssh-s2-" + Date.now(),
            sender: "copilot",
            timestamp: Date.now(),
            text: `Got host: **${host}** (Port: ${port}).\n\n**Step 2 of 4**: What **username** do you log in with?\n(Press Enter or click a button for common defaults)`,
            chips: [
              { label: `Use ${username}`, query: username },
              { label: "root", query: "root" },
              { label: "ubuntu", query: "ubuntu" },
              { label: "ec2-user", query: "ec2-user" },
            ],
          },
        ]);
        setBusy(false);
        return;
      }

      if (step === 2) {
        // Step 2: Username
        data.username = q.trim();
        setWizard({ mode: "ssh", step: 3, data });
        setMessages((prev) => [
          ...prev,
          {
            id: "ssh-s3-" + Date.now(),
            sender: "copilot",
            timestamp: Date.now(),
            text: `Username set to **${data.username}**.\n\n**Step 3 of 4**: How do you authenticate with this server?`,
            chips: [
              { label: "🔑 Password", query: "password" },
              { label: "📜 SSH Private Key", query: "key" },
            ],
          },
        ]);
        setBusy(false);
        return;
      }

      if (step === 3) {
        // Step 3: Auth type
        const isKey = lower.includes("key") || lower.includes("pem");
        data.auth_method = isKey ? "key" : "password";
        setWizard({ mode: "ssh", step: 4, data });
        setMessages((prev) => [
          ...prev,
          {
            id: "ssh-s4-" + Date.now(),
            sender: "copilot",
            timestamp: Date.now(),
            text: isKey
              ? `Selected **SSH Private Key**.\n\n**Step 4 of 4**: Paste your private key text or type 'skip' if you plan to attach a key file later.`
              : `Selected **Password**.\n\n**Step 4 of 4**: Enter your server password. It will be encrypted immediately into your vault.`,
          },
        ]);
        setBusy(false);
        return;
      }

      if (step === 4) {
        // Step 4: Password or Key content
        if (data.auth_method === "password") {
          data.password = q.trim();
        } else if (lower !== "skip") {
          data.private_key = q.trim();
        }

        const title = `SSH - ${data.host}`;
        const finalValues: Record<string, string> = { ...data };
        setWizard({ mode: "idle", step: 0, data: {} });

        // Build Action Card
        const actionCard: CopilotActionCard = {
          title,
          subtitle: `${data.username}@${data.host}:${data.port || "22"} (${data.auth_method})`,
          fields: finalValues,
          recordType: "ssh_server",
          tags: ["SSH", "Server", "Remote"],
          primaryLabel: "Save & Connect Now",
          onPrimary: async () => {
            const valuesList = Object.entries(finalValues);
            const id = await ipc.createRecord(
              "ssh_server",
              title,
              "",
              ["SSH", "Server", "Remote"],
              valuesList,
            );
            onRecordCreated(id);
            try {
              await ipc.sshConnect(id);
            } catch (err) {
              setMessages((m) => [
                ...m,
                {
                  id: "conn-err-" + Date.now(),
                  sender: "copilot",
                  timestamp: Date.now(),
                  text: `⚠️ Record saved, but launching terminal returned: ${asAppError(err).message}`,
                },
              ]);
            }
          },
          secondaryLabel: "Save to Vault Only",
          onSecondary: async () => {
            const valuesList = Object.entries(finalValues);
            const id = await ipc.createRecord(
              "ssh_server",
              title,
              "",
              ["SSH", "Server", "Remote"],
              valuesList,
            );
            onRecordCreated(id);
            setMessages((m) => [
              ...m,
              {
                id: "saved-" + Date.now(),
                sender: "copilot",
                timestamp: Date.now(),
                text: `✅ Saved **${title}** to your vault! You can connect anytime using the [ Connect ] button in the record bar.`,
              },
            ]);
          },
          editLabel: "Open in Editor",
          onEdit: () => {
            onOpenNewRecord("ssh_server", finalValues, title);
          },
        };

        setMessages((prev) => [
          ...prev,
          {
            id: "ssh-finish-" + Date.now(),
            sender: "copilot",
            timestamp: Date.now(),
            text: `🎉 Server details collected! What would you like to do?`,
            actionCard,
          },
        ]);
        setBusy(false);
        return;
      }
    }

    // -------------------------------------------------------------
    // RAW CREDENTIALS / CONNECTION STRING DETECTION
    // -------------------------------------------------------------
    const parsed = parseRawCredentials(q);
    if (parsed) {
      if (parsed.type === "ssh") {
        const actionCard: CopilotActionCard = {
          title: parsed.title,
          subtitle: `${parsed.username}@${parsed.host}:${parsed.port} (${parsed.authMethod})`,
          fields: parsed.fields,
          recordType: "ssh_server",
          tags: parsed.tags,
          primaryLabel: "Save & Connect Now",
          onPrimary: async () => {
            const valuesList = Object.entries(parsed.fields);
            const id = await ipc.createRecord(
              "ssh_server",
              parsed.title,
              "",
              parsed.tags,
              valuesList,
            );
            onRecordCreated(id);
            try {
              await ipc.sshConnect(id);
            } catch (err) {
              setMessages((m) => [
                ...m,
                {
                  id: "conn-err-" + Date.now(),
                  sender: "copilot",
                  timestamp: Date.now(),
                  text: `⚠️ Saved to vault, but launching SSH failed: ${asAppError(err).message}`,
                },
              ]);
            }
          },
          secondaryLabel: "Save Record",
          onSecondary: async () => {
            const valuesList = Object.entries(parsed.fields);
            const id = await ipc.createRecord(
              "ssh_server",
              parsed.title,
              "",
              parsed.tags,
              valuesList,
            );
            onRecordCreated(id);
            setMessages((m) => [
              ...m,
              {
                id: "saved-" + Date.now(),
                sender: "copilot",
                timestamp: Date.now(),
                text: `✅ Saved **${parsed.title}** to your vault!`,
              },
            ]);
          },
          editLabel: "Customize Fields",
          onEdit: () => {
            onOpenNewRecord("ssh_server", parsed.fields, parsed.title);
          },
        };

        setMessages((prev) => [
          ...prev,
          {
            id: "parsed-ssh-" + Date.now(),
            sender: "copilot",
            timestamp: Date.now(),
            text: `I detected an SSH connection request for **${parsed.username}@${parsed.host}**:\n- **Host**: \`${parsed.host}\`\n- **Port**: \`${parsed.port}\`\n- **Username**: \`${parsed.username}\`\n- **Password**: \`••••••••\` (Detected)`,
            actionCard,
          },
        ]);
        setBusy(false);
        return;
      }

      if (parsed.type === "cloud") {
        const actionCard: CopilotActionCard = {
          title: parsed.title,
          subtitle: `Provider: ${parsed.provider?.toUpperCase()}`,
          fields: parsed.fields,
          recordType: "cloud_service_account",
          tags: parsed.tags,
          primaryLabel: "Save & Launch Cloud Shell",
          onPrimary: async () => {
            const valuesList = Object.entries(parsed.fields);
            const id = await ipc.createRecord(
              "cloud_service_account",
              parsed.title,
              "",
              parsed.tags,
              valuesList,
            );
            onRecordCreated(id);
            try {
              await ipc.cloudConnect(id, parsed.provider);
            } catch (err) {
              setMessages((m) => [
                ...m,
                {
                  id: "cloud-err-" + Date.now(),
                  sender: "copilot",
                  timestamp: Date.now(),
                  text: `⚠️ Saved to vault, but launching Cloud Shell returned: ${asAppError(err).message}`,
                },
              ]);
            }
          },
          secondaryLabel: "Save Record Only",
          onSecondary: async () => {
            const valuesList = Object.entries(parsed.fields);
            const id = await ipc.createRecord(
              "cloud_service_account",
              parsed.title,
              "",
              parsed.tags,
              valuesList,
            );
            onRecordCreated(id);
          },
          editLabel: "Customize Fields",
          onEdit: () => {
            onOpenNewRecord("cloud_service_account", parsed.fields, parsed.title);
          },
        };

        setMessages((prev) => [
          ...prev,
          {
            id: "parsed-cloud-" + Date.now(),
            sender: "copilot",
            timestamp: Date.now(),
            text: `Detected Cloud credentials for **${parsed.provider?.toUpperCase()}**:\n- **Access Key ID**: \`${parsed.fields.access_key_id}\`\n- **Region**: \`${parsed.fields.default_region}\``,
            actionCard,
          },
        ]);
        setBusy(false);
        return;
      }
    }

    // -------------------------------------------------------------
    // INTENT DISPATCHER
    // -------------------------------------------------------------

    // 1. Wizard initiation: "connect to a server", "setup ssh"
    if (
      lower.includes("connect to a server") ||
      lower.includes("setup ssh") ||
      lower.includes("new server") ||
      lower.includes("add server") ||
      (lower.includes("connect") && lower.includes("server"))
    ) {
      setWizard({ mode: "ssh", step: 1, data: {} });
      setMessages((prev) => [
        ...prev,
        {
          id: "wiz-start-" + Date.now(),
          sender: "copilot",
          timestamp: Date.now(),
          text: `I will guide you step-by-step through setting up your SSH server!\n\n**Step 1 of 4**: What is the **IP address or domain** of your server?\n(e.g. \`94.136.186.9\` or \`myserver.cloud.com\`)`,
          chips: [
            { label: "94.136.186.9", query: "94.136.186.9" },
            { label: "192.168.1.100", query: "192.168.1.100" },
            { label: "Cancel", query: "cancel" },
          ],
        },
      ]);
      setBusy(false);
      return;
    }

    // 2. Direct Actions: Open dialogs, search, backup, lock, password generation
    if (
      lower.includes("new record") ||
      lower.includes("create record") ||
      lower.includes("add password")
    ) {
      onOpenNewRecord();
      setMessages((prev) => [
        ...prev,
        {
          id: "act-new-" + Date.now(),
          sender: "copilot",
          timestamp: Date.now(),
          text: "I opened the **New Record Dialog** for you. Choose a template or paste your connection string at the top.",
        },
      ]);
      setBusy(false);
      return;
    }

    if (lower.includes("setting") || lower.includes("preferences")) {
      onOpenSettings();
      setMessages((prev) => [
        ...prev,
        {
          id: "act-set-" + Date.now(),
          sender: "copilot",
          timestamp: Date.now(),
          text: "I opened the **Settings** view for you. You can configure automatic backups, quick unlock hotkeys, and export your vault.",
        },
      ]);
      setBusy(false);
      return;
    }

    if (lower.startsWith("search ") || lower.startsWith("find ")) {
      const searchTerm = q.replace(/^(search|find)\s+(for\s+)?/i, "").trim();
      onSearch(searchTerm);
      setMessages((prev) => [
        ...prev,
        {
          id: "act-search-" + Date.now(),
          sender: "copilot",
          timestamp: Date.now(),
          text: `Filtered your vault records for: **"${searchTerm}"**. Check the record list on the left.`,
        },
      ]);
      setBusy(false);
      return;
    }

    if (lower.includes("backup now") || lower.includes("create backup")) {
      try {
        const snap = await ipc.backupNow();
        setMessages((prev) => [
          ...prev,
          {
            id: "act-bk-" + Date.now(),
            sender: "copilot",
            timestamp: Date.now(),
            text: `✅ **Backup successfully created!**\n- **File**: \`${snap.path}\`\n- **Records saved**: ${snap.recordCount}\n- **Created at**: ${new Date(snap.createdAt * 1000).toLocaleTimeString()}`,
          },
        ]);
      } catch (err) {
        setMessages((prev) => [
          ...prev,
          {
            id: "act-bk-err-" + Date.now(),
            sender: "copilot",
            timestamp: Date.now(),
            text: `⚠️ Backup failed: ${asAppError(err).message}`,
          },
        ]);
      }
      setBusy(false);
      return;
    }

    if (lower.includes("generate password") || lower.includes("random password")) {
      try {
        const pass = await ipc.generatePassword({
          length: 24,
          uppercase: true,
          lowercase: true,
          digits: true,
          symbols: true,
        });
        setMessages((prev) => [
          ...prev,
          {
            id: "act-pw-" + Date.now(),
            sender: "copilot",
            timestamp: Date.now(),
            text: `Generated high-entropy password (24 characters, ~130 bits entropy):`,
            codeSnippet: {
              language: "text",
              code: pass.value,
              title: "Generated Password",
            },
          },
        ]);
      } catch (err) {
        setMessages((prev) => [
          ...prev,
          {
            id: "act-pw-err-" + Date.now(),
            sender: "copilot",
            timestamp: Date.now(),
            text: `⚠️ Password generation failed: ${asAppError(err).message}`,
          },
        ]);
      }
      setBusy(false);
      return;
    }

    // -------------------------------------------------------------
    // SSH TROUBLESHOOTING KNOWLEDGE BASE
    // -------------------------------------------------------------
    if (
      lower.includes("wrong password") ||
      lower.includes("permission denied") ||
      lower.includes("access denied") ||
      lower.includes("auth fail")
    ) {
      setMessages((prev) => [
        ...prev,
        {
          id: "ssh-trouble-" + Date.now(),
          sender: "copilot",
          timestamp: Date.now(),
          text: `### SSH Authentication Troubleshooting Guide\n\nWhen a server responds with **"Wrong password"** or **"Permission denied (publickey,password)"**, it is almost always caused by one of these server configurations:`,
          troubleshooting: {
            cause:
              "Ubuntu, Debian, and Cloud VPS providers disable password authentication or root password login by default.",
            steps: [
              "1. Remote SSH config: Modern distributions have 'PermitRootLogin prohibit-password' in /etc/ssh/sshd_config. This means root cannot log in with a password, only with an SSH key.",
              "2. PasswordAuthentication: Check if 'PasswordAuthentication no' is set on the remote server.",
              "3. Fail2ban: If you attempted multiple connections, Fail2ban may have temporarily blocked your IP for 10-15 minutes.",
              "4. Recommend SSH Key Auth: In Keyring, switch Auth Method to 'SSH Private Key', generate an ed25519 key, and append it to ~/.ssh/authorized_keys on the server.",
            ],
            fixCommand:
              "# On your remote server console:\nsudo nano /etc/ssh/sshd_config\n# Ensure:\n# PasswordAuthentication yes\n# PermitRootLogin yes\nsudo systemctl restart ssh",
          },
          chips: [
            { label: "Switch to SSH Key auth", query: "How to use SSH keys instead of password?" },
            { label: "Host key verification failed?", query: "Host key verification failed fix" },
          ],
        },
      ]);
      setBusy(false);
      return;
    }

    if (lower.includes("host key") || lower.includes("identification has changed")) {
      setMessages((prev) => [
        ...prev,
        {
          id: "host-key-" + Date.now(),
          sender: "copilot",
          timestamp: Date.now(),
          text: `### Remote Host Identification Has Changed\n\nThis happens when a server is re-installed or an IP address is reassigned to a new machine. OpenSSH blocks the connection to protect you against man-in-the-middle attacks.\n\n**To resolve:** Clear the old fingerprint from your local \`known_hosts\` file:`,
          codeSnippet: {
            language: "powershell",
            code: "ssh-keygen -R <server-ip-or-hostname>",
            title: "Remove cached host key in PowerShell / CMD",
          },
        },
      ]);
      setBusy(false);
      return;
    }

    if (lower.includes("putty") || lower.includes(".ppk") || lower.includes("convert key")) {
      setMessages((prev) => [
        ...prev,
        {
          id: "ppk-" + Date.now(),
          sender: "copilot",
          timestamp: Date.now(),
          text: `### Converting PuTTY (.ppk) to OpenSSH (.pem)\n\nKeyring and OpenSSH use the standard OpenSSH / PEM key format. If you have a PuTTY \`.ppk\` file, convert it using \`puttygen\` or open it in PuTTYgen GUI (Conversions -> Export OpenSSH key):`,
          codeSnippet: {
            language: "bash",
            code: "puttygen mykey.ppk -O private-openssh -o id_rsa",
            title: "Convert .ppk to OpenSSH",
          },
        },
      ]);
      setBusy(false);
      return;
    }

    // -------------------------------------------------------------
    // CLOUD CLI INTEGRATION KNOWLEDGE BASE
    // -------------------------------------------------------------
    if (
      lower.includes("cloud cli") ||
      lower.includes("aws") ||
      lower.includes("azure") ||
      lower.includes("gcp") ||
      lower.includes("kubernetes")
    ) {
      setMessages((prev) => [
        ...prev,
        {
          id: "cloud-info-" + Date.now(),
          sender: "copilot",
          timestamp: Date.now(),
          text: `### Cloud CLI Integration in Keyring\n\nKeyring lets you securely store IAM credentials and launch **pre-authenticated Cloud Shells** without persisting secrets to disk in plaintext:\n\n- **AWS**: Injects \`AWS_ACCESS_KEY_ID\`, \`AWS_SECRET_ACCESS_KEY\`, and \`AWS_DEFAULT_REGION\` into an ephemeral PowerShell session.\n- **GCP**: Injects \`CLOUDSDK_CORE_PROJECT\` and service account credentials.\n- **Azure**: Automates Service Principal authentication (\`az login --service-principal\`).\n- **Kubernetes**: Sets \`KUBECONFIG\` pointing to your vaulted cluster configuration.`,
          codeSnippet: {
            language: "powershell",
            code: "# To verify your AWS credentials after launching:\naws sts get-caller-identity\n\n# To verify Azure:\naz account show\n\n# To verify Kubernetes:\nkubectl get nodes",
            title: "Verification Commands",
          },
          chips: [
            { label: "Add AWS account now", query: "Setup AWS credentials" },
            { label: "Create Cloud Record", query: "Create record" },
          ],
        },
      ]);
      setBusy(false);
      return;
    }

    // -------------------------------------------------------------
    // SECURITY & ZERO-TRUST KNOWLEDGE BASE
    // -------------------------------------------------------------
    if (
      lower.includes("encrypt") ||
      lower.includes("security") ||
      lower.includes("argon2") ||
      lower.includes("zeroize") ||
      lower.includes("zero network") ||
      lower.includes("safe") ||
      lower.includes("decompile")
    ) {
      setMessages((prev) => [
        ...prev,
        {
          id: "sec-info-" + Date.now(),
          sender: "copilot",
          timestamp: Date.now(),
          text: `### Keyring Zero-Trust Security Architecture 🛡️\n\nKeyring is built from the ground up for high-security environments:\n\n1. **Cryptographic Envelope**: Master passwords derive an encryption key via **Argon2id** (memory-hard, resistant to GPU/ASIC clusters). Vault data is encrypted with **XChaCha20-Poly1305** (256-bit key, 192-bit nonce, AEAD authenticated cipher).\n2. **100% Zero-Network Policy**: Keyring compiles with zero network sockets. There is no telemetry, no cloud sync, and no internet communication. Your secrets physically cannot be exfiltrated.\n3. **Memory Zeroization**: Plaintext secrets in Rust implement the \`Zeroize\` trait, which unconditionally overwrites secret bytes in RAM with zeros immediately on drop.\n4. **Anti-Decompilation & Anti-Debug**: Windows release builds feature active debugger detection (\`IsDebuggerPresent\`) and production bundles strip all comments, identifiers, and sourcemaps.`,
        },
      ]);
      setBusy(false);
      return;
    }

    // -------------------------------------------------------------
    // OUT-OF-SCOPE HANDLER (What the Agent CANNOT do + Next Steps)
    // -------------------------------------------------------------
    const isNetworkQuery =
      lower.includes("browse") ||
      lower.includes("internet") ||
      lower.includes("google") ||
      lower.includes("weather") ||
      lower.includes("send email") ||
      lower.includes("download from web") ||
      lower.includes("http") ||
      lower.includes("curl ") ||
      lower.includes("ping google");

    const isResetPasswordQuery =
      lower.includes("forgot my master password") ||
      lower.includes("reset master password") ||
      lower.includes("recover master password") ||
      lower.includes("bypass password") ||
      lower.includes("crack password");

    const isRemoteExecQuery =
      lower.includes("hack") ||
      lower.includes("ddos") ||
      lower.includes("run rm -rf") ||
      lower.includes("reboot server") ||
      lower.includes("install nginx on server");

    const isFirewallQuery =
      lower.includes("open port on aws") ||
      lower.includes("modify security group") ||
      lower.includes("create vpc") ||
      lower.includes("open firewall");

    if (isNetworkQuery) {
      setMessages((prev) => [
        ...prev,
        {
          id: "oos-net-" + Date.now(),
          sender: "copilot",
          timestamp: Date.now(),
          text: `⚠️ **Action Outside Assistant Capability**`,
          outOfScope: {
            limitation: "Cannot make outbound HTTP / internet requests or browse websites.",
            why: "Keyring is built with a strict Zero-Network security guarantee. The application has no network socket capabilities compiled into it, ensuring zero data leakage.",
            nextSteps: [
              "Perform the web browsing or API request in your standard web browser or terminal.",
              "If the service requires an API Key, Bearer Token, or Webhook Secret, store it safely in Keyring under an 'API Credential' record.",
            ],
            externalAction: "Use Chrome / Edge / curl in your native terminal",
          },
          chips: [
            { label: "Create API Credential Record", query: "Create record" },
            { label: "Vault Security Details", query: "How is my vault encrypted?" },
          ],
        },
      ]);
      setBusy(false);
      return;
    }

    if (isResetPasswordQuery) {
      setMessages((prev) => [
        ...prev,
        {
          id: "oos-pw-" + Date.now(),
          sender: "copilot",
          timestamp: Date.now(),
          text: `⚠️ **Zero-Knowledge Architecture Limitation**`,
          outOfScope: {
            limitation: "Cannot recover, bypass, or reset a forgotten Master Password.",
            why: "Keyring is mathematically zero-knowledge. Your encryption key is derived directly from your master password using Argon2id. There are no master backdoor keys, no cloud resets, and no recovery questions.",
            nextSteps: [
              "Check if you have an unencrypted export or paper backup stored in a safe physical location.",
              "If you recently changed your master password, check your automated backup directory (Settings -> Backups) for snapshots encrypted with your previous password.",
              "If the master password is permanently lost, you will need to create a new vault.",
            ],
          },
          chips: [
            { label: "Open Settings & Backups", query: "Open settings" },
            { label: "Vault Security Explanation", query: "Vault security architecture" },
          ],
        },
      ]);
      setBusy(false);
      return;
    }

    if (isRemoteExecQuery) {
      setMessages((prev) => [
        ...prev,
        {
          id: "oos-exec-" + Date.now(),
          sender: "copilot",
          timestamp: Date.now(),
          text: `⚠️ **Security Boundary**`,
          outOfScope: {
            limitation:
              "Cannot run arbitrary administrative scripts or commands on remote servers in the background.",
            why: "Keyring is an identity and secret vault, not a blind remote execution agent. For security and auditability, all server interactions must occur inside your authorized, interactive terminal session.",
            nextSteps: [
              "Click the [ Connect ] button on your SSH record to launch an interactive terminal window.",
              "Run your administrative commands directly within that authenticated shell.",
            ],
            externalAction: "Click [ Connect ] in the top action bar to launch PowerShell/SSH",
          },
        },
      ]);
      setBusy(false);
      return;
    }

    if (isFirewallQuery) {
      setMessages((prev) => [
        ...prev,
        {
          id: "oos-fw-" + Date.now(),
          sender: "copilot",
          timestamp: Date.now(),
          text: `⚠️ **Cloud Infrastructure Boundary**`,
          outOfScope: {
            limitation: "Cannot directly alter remote Cloud Security Groups or VPC Firewalls.",
            why: "Keyring manages identity credentials and launches authenticated CLI sessions, but does not manipulate cloud networking infrastructure directly.",
            nextSteps: [
              "Log into your AWS / GCP / Azure web console.",
              "Navigate to EC2 -> Security Groups (or VPC Firewall Rules).",
              "Add an Inbound Rule: Protocol TCP, Port 22 (SSH), Source: Your Current IP (/32).",
              "Once saved, return to Keyring and click [ Connect ].",
            ],
          },
        },
      ]);
      setBusy(false);
      return;
    }

    // -------------------------------------------------------------
    // GENERAL FALLBACK WITH HELPFUL NEXT STEPS
    // -------------------------------------------------------------
    setMessages((prev) => [
      ...prev,
      {
        id: "fallback-" + Date.now(),
        sender: "copilot",
        timestamp: Date.now(),
        text: `I understand you're asking about: **"${q}"**.\n\nWhile I don't have a specialized automation for that exact phrase, here is how you can proceed:`,
        outOfScope: {
          limitation: "Unhandled query or outside vault management scope.",
          why: "Keyring Copilot is a local-only assistant specializing in vault management, SSH/Cloud connectivity, zero-trust security, and credentials.",
          nextSteps: [
            "Paste an SSH connection string directly (e.g. `ssh root@94.136.186.9 pass: s5i8U2jO7`) to auto-save and connect.",
            "Ask for help with SSH troubleshooting, Cloud CLI setup, or password generation.",
            "Use the quick action buttons below to navigate to key vault features.",
          ],
        },
        chips: [
          { label: "🚀 Connect to an SSH server", query: "I want to connect to a server" },
          { label: "☁️ Add Cloud credentials", query: "Setup AWS credentials" },
          { label: "❓ SSH 'Wrong Password' fix", query: "Why is SSH saying wrong password?" },
          { label: "🔑 Generate password", query: "Generate a strong password" },
          { label: "💾 Create backup", query: "Create backup now" },
        ],
      },
    ]);
    setBusy(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void handleUserMessage(input);
    }
  };

  if (!isOpen) return null;

  return (
    <aside
      className="fixed top-10 right-0 bottom-0 w-[420px] max-w-full z-40 bg-panel border-l border-edge shadow-2xl flex flex-col select-text"
      aria-label="Keyring Copilot"
    >
      {/* Header */}
      <div className="h-12 shrink-0 px-4 flex items-center justify-between border-b border-edge bg-void/40">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded-control bg-accent/20 border border-accent/40 flex items-center justify-center text-accent">
            <Sparkles size={14} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-text">Keyring Copilot</span>
              <span className="inline-flex items-center gap-1 px-1.5 py-0.2 rounded-tag bg-ok/10 text-ok text-[10px] font-mono border border-ok/20">
                <span className="w-1.5 h-1.5 rounded-full bg-ok" />
                Offline
              </span>
            </div>
            <p className="text-[11px] text-text-dim">Zero-Network Local Assistant</p>
          </div>
        </div>

        <div className="flex items-center gap-1">
          <button
            onClick={resetChat}
            title="Reset conversation"
            className="p-1.5 rounded-control text-text-dim hover:text-text hover:bg-panel-hi transition-colors"
          >
            <RotateCcw size={14} />
          </button>
          <button
            onClick={onClose}
            title="Close Copilot (Esc)"
            className="p-1.5 rounded-control text-text-dim hover:text-text hover:bg-panel-hi transition-colors"
          >
            <X size={16} />
          </button>
        </div>
      </div>

      {/* Message History */}
      <div
        ref={scrollRef}
        className="flex-1 min-h-0 overflow-y-auto p-4 space-y-4 font-ui text-sm"
      >
        {messages.map((m) => (
          <div
            key={m.id}
            className={clsx(
              "flex flex-col gap-1.5 max-w-[95%]",
              m.sender === "user" ? "ml-auto items-end" : "mr-auto items-start",
            )}
          >
            {/* Sender Label */}
            <div className="flex items-center gap-1.5 text-[11px] text-text-faint px-1">
              {m.sender === "copilot" ? (
                <>
                  <Sparkles size={11} className="text-accent" />
                  <span>Keyring Copilot</span>
                </>
              ) : (
                <span>You</span>
              )}
              <span>•</span>
              <span>{new Date(m.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
            </div>

            {/* Bubble */}
            <div
              className={clsx(
                "p-3 rounded-panel text-sm leading-relaxed border transition-all",
                m.sender === "user"
                  ? "bg-accent/15 border-accent/30 text-text"
                  : "bg-void/80 border-edge text-text",
              )}
            >
              <div className="whitespace-pre-wrap">{m.text}</div>

              {/* Troubleshooting Card */}
              {m.troubleshooting && (
                <div className="mt-3 p-3 rounded-control bg-panel border border-warn/30 text-xs">
                  <div className="flex items-center gap-1.5 text-warn font-medium mb-1">
                    <AlertCircle size={13} />
                    <span>Potential Root Cause:</span>
                  </div>
                  <p className="text-text-dim mb-2">{m.troubleshooting.cause}</p>
                  <div className="text-[11px] font-medium text-text mb-1">Resolution Checklist:</div>
                  <ul className="space-y-1 text-text-dim pl-2">
                    {m.troubleshooting.steps.map((step, i) => (
                      <li key={i}>{step}</li>
                    ))}
                  </ul>
                  {m.troubleshooting.fixCommand && (
                    <div className="mt-2 pt-2 border-t border-edge">
                      <div className="flex items-center justify-between text-[11px] text-text-faint mb-1">
                        <span>Remote Fix Commands:</span>
                        <button
                          onClick={() => copyToClipboard(m.troubleshooting?.fixCommand ?? "", m.id + "-fix")}
                          className="flex items-center gap-1 text-accent hover:underline text-[10px]"
                        >
                          {copiedId === m.id + "-fix" ? (
                            <>
                              <Check size={10} /> Copied
                            </>
                          ) : (
                            <>
                              <Copy size={10} /> Copy
                            </>
                          )}
                        </button>
                      </div>
                      <pre className="font-data text-[11px] bg-void/90 p-2 rounded-control text-accent overflow-x-auto">
                        {m.troubleshooting.fixCommand}
                      </pre>
                    </div>
                  )}
                </div>
              )}

              {/* Out of Scope / Limitation Card */}
              {m.outOfScope && (
                <div className="mt-3 p-3 rounded-control bg-panel border border-edge-strong text-xs">
                  <div className="flex items-center gap-1.5 text-text font-medium mb-1">
                    <Shield size={13} className="text-accent" />
                    <span>Zero-Trust Boundary:</span>
                  </div>
                  <p className="text-text-dim mb-1">
                    <strong className="text-text">Limitation:</strong> {m.outOfScope.limitation}
                  </p>
                  <p className="text-text-dim mb-2">
                    <strong className="text-text">Why:</strong> {m.outOfScope.why}
                  </p>

                  <div className="text-[11px] font-medium text-ok mb-1">Recommended Next Steps:</div>
                  <ul className="space-y-1 text-text-dim pl-2 list-disc list-inside">
                    {m.outOfScope.nextSteps.map((step, i) => (
                      <li key={i}>{step}</li>
                    ))}
                  </ul>

                  {m.outOfScope.externalAction && (
                    <div className="mt-2.5 p-1.5 rounded-tag bg-void text-text-dim flex items-center gap-2 text-[11px]">
                      <ArrowRight size={12} className="text-accent" />
                      <span>{m.outOfScope.externalAction}</span>
                    </div>
                  )}
                </div>
              )}

              {/* Code Snippet */}
              {m.codeSnippet && (
                <div className="mt-2 rounded-control bg-void border border-edge overflow-hidden">
                  <div className="px-2.5 py-1 bg-panel-hi/50 border-b border-edge flex items-center justify-between text-[11px] text-text-faint">
                    <span>{m.codeSnippet.title || m.codeSnippet.language}</span>
                    <button
                      onClick={() => copyToClipboard(m.codeSnippet?.code ?? "", m.id)}
                      className="flex items-center gap-1 text-accent hover:text-accent-hi transition-colors"
                    >
                      {copiedId === m.id ? (
                        <>
                          <Check size={11} /> Copied
                        </>
                      ) : (
                        <>
                          <Copy size={11} /> Copy
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="p-2.5 font-data text-xs text-text overflow-x-auto whitespace-pre-wrap">
                    {m.codeSnippet.code}
                  </pre>
                </div>
              )}

              {/* Action Card */}
              {m.actionCard && (
                <div className="mt-3 p-3 rounded-control bg-panel border border-accent/40 shadow-md">
                  <div className="flex items-center gap-2 mb-2">
                    <Server size={15} className="text-accent" />
                    <div>
                      <div className="font-semibold text-text text-sm">
                        {m.actionCard.title}
                      </div>
                      {m.actionCard.subtitle && (
                        <div className="text-[11px] text-text-dim">
                          {m.actionCard.subtitle}
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-1.5 text-xs bg-void/50 p-2 rounded-tag border border-edge mb-3 font-data">
                    {Object.entries(m.actionCard.fields)
                      .filter(([k]) => !k.includes("private_key") && !k.includes("secret"))
                      .slice(0, 4)
                      .map(([k, v]) => (
                        <div key={k} className="truncate">
                          <span className="text-text-faint">{k}: </span>
                          <span className="text-text">{v}</span>
                        </div>
                      ))}
                    {m.actionCard.fields.password && (
                      <div className="truncate col-span-2">
                        <span className="text-text-faint">password: </span>
                        <span className="text-accent">•••••••• (Encrypted)</span>
                      </div>
                    )}
                  </div>

                  <div className="flex flex-col gap-2">
                    <Button
                      variant="primary"
                      onClick={() => void m.actionCard?.onPrimary()}
                      className="w-full justify-center h-8 text-xs font-semibold"
                    >
                      <Terminal size={13} className="mr-1.5" />
                      {m.actionCard.primaryLabel}
                    </Button>

                    <div className="flex gap-2">
                      {m.actionCard.secondaryLabel && (
                        <button
                          type="button"
                          onClick={() => void m.actionCard?.onSecondary?.()}
                          className="flex-1 justify-center h-7 text-xs rounded-control bg-panel-hi border border-edge hover:bg-panel hover:text-text text-text-dim transition-colors"
                        >
                          {m.actionCard.secondaryLabel}
                        </button>
                      )}
                      {m.actionCard.editLabel && (
                        <Button
                          variant="ghost"
                          onClick={() => m.actionCard?.onEdit?.()}
                          className="flex-1 justify-center h-7 text-xs text-text-dim"
                        >
                          {m.actionCard.editLabel}
                        </Button>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Quick Chips */}
            {m.chips && m.chips.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-1">
                {m.chips.map((chip, idx) => (
                  <button
                    key={idx}
                    onClick={() => void handleUserMessage(chip.query)}
                    className="px-2.5 py-1 rounded-full bg-panel-hi/60 hover:bg-accent/20 border border-edge hover:border-accent/40 text-xs text-text-dim hover:text-text transition-colors text-left"
                  >
                    {chip.label}
                  </button>
                ))}
              </div>
            )}
          </div>
        ))}

        {busy && (
          <div className="flex items-center gap-2 text-text-faint text-xs pl-2">
            <RefreshCw size={12} className="animate-spin text-accent" />
            <span>Copilot is processing...</span>
          </div>
        )}
      </div>

      {/* Input bar */}
      <div className="p-3 border-t border-edge bg-void/60">
        <div className="flex items-center justify-between text-[11px] text-text-faint mb-1.5 px-1">
          <span>Ask or paste credentials (e.g. ssh root@94.136.186.9 pass: ...)</span>
          <span>100% Offline</span>
        </div>
        <div className="relative flex items-end rounded-control bg-panel border border-edge focus-within:border-accent">
          <textarea
            ref={inputRef}
            rows={2}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask Copilot a question, paste SSH details, or type 'help'..."
            className="w-full resize-none p-2.5 pr-10 bg-transparent text-sm text-text placeholder:text-text-faint focus:outline-none font-ui"
          />
          <button
            onClick={() => void handleUserMessage(input)}
            disabled={!input.trim() || busy}
            className="absolute right-2 bottom-2 p-1.5 rounded-control bg-accent text-void disabled:opacity-40 disabled:hover:bg-accent hover:bg-accent-hi transition-colors"
            title="Send (Enter)"
          >
            <Send size={13} />
          </button>
        </div>
        <div className="flex items-center justify-between text-[10px] text-text-faint mt-1.5 px-1">
          <span>
            <Kbd>Enter</Kbd> to send • <Kbd>Shift+Enter</Kbd> for newline
          </span>
          <span>
            <Kbd>Esc</Kbd> to close
          </span>
        </div>
      </div>
    </aside>
  );
}
