import { useEffect, useMemo, useState } from "react";

import {
    removeGroupMember,
    leaveGroup,
    transferGroupAdmin,
    deleteGroup,
    dismissGroupAdmin,
    resignGroupAdmin,
} from "../services/conversationService.js";

/* ==================================================
   SAFE VALUE HELPERS
================================================== */

function getId(value) {
    if (value === null || value === undefined) return "";

    if (typeof value === "string" || typeof value === "number") {
        return String(value);
    }

    if (typeof value === "object") {
        if (value._id) return getId(value._id);
        if (value.id) return getId(value.id);
        if (value.userId) return getId(value.userId);
        if (value.user?._id) return getId(value.user._id);
        if (value.user?.id) return getId(value.user.id);
    }

    return "";
}

function getDisplayValue(value, fallback = "") {
    if (value === null || value === undefined) return fallback;

    if (
        typeof value === "string" ||
        typeof value === "number" ||
        typeof value === "boolean"
    ) {
        return String(value);
    }

    if (Array.isArray(value)) {
        return value
            .map((item) => getDisplayValue(item))
            .filter(Boolean)
            .join(", ");
    }

    if (typeof value === "object") {
        const candidate =
            value.name ||
            value.fullName ||
            value.email ||
            value.username ||
            value.text ||
            value.message;

        if (candidate !== undefined) {
            return getDisplayValue(candidate, fallback);
        }
    }

    return fallback;
}

function getParticipantId(member) {
    return getId(member);
}

function getParticipantName(member) {
    return getDisplayValue(
        member?.name ||
        member?.fullName ||
        member?.user?.name ||
        member?.user?.fullName ||
        member?.email ||
        member?.user?.email,
        "SecureX Member"
    );
}

function getParticipantEmail(member) {
    return getDisplayValue(
        member?.email || member?.user?.email,
        "Group participant"
    );
}

function getErrorMessage(error) {
    if (typeof error === "string") return error;

    if (typeof error?.message === "string") {
        return error.message;
    }

    if (typeof error?.response?.data?.message === "string") {
        return error.response.data.message;
    }

    return "Unable to complete this action. Please try again.";
}

/* ==================================================
   MULTIPLE ADMIN HELPERS
================================================== */

function getGroupAdminIds(conversation) {
    const admins = Array.isArray(conversation?.groupAdmins)
        ? conversation.groupAdmins.map(getId).filter(Boolean)
        : [];

    // Prefer groupAdmins when available.
    // Use the legacy field only for older conversations.
    if (admins.length > 0) {
        return [...new Set(admins)];
    }

    const legacyAdmin = getId(
        conversation?.groupAdmin || conversation?.admin
    );

    if (legacyAdmin) {
        return [legacyAdmin];
    }

    if (conversation?.createdBy) {
        const creatorId = getId(conversation.createdBy);

        if (creatorId) return [creatorId];
    }

    return [];
}

/* ==================================================
   PROFESSIONAL SVG ICONS
================================================== */

function Icon({ name, size = 18 }) {
    const common = {
        width: size,
        height: size,
        viewBox: "0 0 24 24",
        fill: "none",
        stroke: "currentColor",
        strokeWidth: 1.7,
        strokeLinecap: "round",
        strokeLinejoin: "round",
        "aria-hidden": true,
    };

    const paths = {
        close: <path d="m18 6-12 12M6 6l12 12" />,

        users: (
            <>
                <circle cx="9" cy="8" r="3" />
                <path d="M3.5 19v-1.2A4.8 4.8 0 0 1 8.3 13h1.4a4.8 4.8 0 0 1 4.8 4.8V19Z" />
                <path d="M16 5.5a3 3 0 0 1 0 5.8M17 13.2a4.7 4.7 0 0 1 3.5 4.6V19h-3" />
            </>
        ),

        plus: <path d="M12 5v14M5 12h14" />,

        remove: (
            <>
                <circle cx="12" cy="12" r="9" />
                <path d="M8 12h8" />
            </>
        ),

        crown: (
            <>
                <path d="m3 8 5 4 4-7 4 7 5-4-2 11H5L3 8Z" />
                <path d="M5 19h14" />
            </>
        ),

        shield: (
            <>
                <path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z" />
                <path d="m9 12 2 2 4-4" />
            </>
        ),

        leave: (
            <>
                <path d="M10 17l5-5-5-5M15 12H3" />
                <path d="M12 3h6a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-6" />
            </>
        ),

        trash: (
            <>
                <path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6" />
                <path d="M10 11v5M14 11v5" />
            </>
        ),

        user: (
            <>
                <circle cx="12" cy="8" r="4" />
                <path d="M4 21a8 8 0 0 1 16 0" />
            </>
        ),

        resign: (
            <>
                <path d="M12 3v12" />
                <path d="m7 10 5 5 5-5" />
                <path d="M5 18v3h14v-3" />
            </>
        ),
    };

    return <svg {...common}>{paths[name] || paths.user}</svg>;
}

/* ==================================================
   GROUP MANAGEMENT PANEL
================================================== */

export default function GroupManagementPanel({
    conversation,
    currentUserId,
    onClose,
    onAddMembers,
    onChanged,
    onRemoved,
}) {
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState("");
    const [confirmation, setConfirmation] = useState(null);

    const conversationId = getId(conversation);
    const currentId = getId(currentUserId);

    const participants = useMemo(
        () =>
            Array.isArray(conversation?.participants)
                ? conversation.participants
                : [],
        [conversation]
    );

    const adminIds = getGroupAdminIds(conversation);

    const isAdmin = Boolean(
        currentId && adminIds.includes(currentId)
    );

    const remainingAdminCount = adminIds.length;

    const groupName = getDisplayValue(
        conversation?.groupName || conversation?.name,
        "SecureX Group"
    );

    const adminMembers = participants.filter((person) =>
        adminIds.includes(getParticipantId(person))
    );

    const adminNames = adminMembers.length
        ? adminMembers.map(getParticipantName).join(", ")
        : "Not assigned";

    /* ==================================================
       KEYBOARD HANDLING
    ================================================== */

    useEffect(() => {
        function handleEscape(event) {
            if (event.key !== "Escape" || busy) return;

            if (confirmation) {
                setConfirmation(null);
                return;
            }

            onClose?.();
        }

        document.addEventListener("keydown", handleEscape);

        return () => {
            document.removeEventListener("keydown", handleEscape);
        };
    }, [busy, confirmation, onClose]);

    /* ==================================================
       COMMON ACTION HANDLER
    ================================================== */

    async function performAction(action, options = {}) {
        if (busy) return;

        try {
            setBusy(true);
            setError("");
            setConfirmation(null);

            await action();

            if (options.removed) {
                onRemoved?.();
                return;
            }

            await onChanged?.();
        } catch (err) {
            setError(getErrorMessage(err));
        } finally {
            setBusy(false);
        }
    }

    /* ==================================================
       GROUP ACTIONS
    ================================================== */

    async function handleRemoveMember(member) {
        const memberId = getParticipantId(member);

        if (!memberId) {
            setError("Could not identify this group member.");
            return;
        }

        await performAction(() =>
            removeGroupMember(conversationId, memberId)
        );
    }

    async function handlePromoteAdmin(member) {
        const memberId = getParticipantId(member);

        if (!memberId) {
            setError("Could not identify this group member.");
            return;
        }

        await performAction(() =>
            transferGroupAdmin(conversationId, memberId)
        );
    }

    async function handleDismissAdmin(member) {
        const memberId = getParticipantId(member);

        if (!memberId) {
            setError("Could not identify this administrator.");
            return;
        }

        await performAction(() =>
            dismissGroupAdmin(conversationId, memberId)
        );
    }

    async function handleResignAdmin() {
        await performAction(() =>
            resignGroupAdmin(conversationId)
        );
    }

    async function handleLeaveGroup() {
        await performAction(
            () => leaveGroup(conversationId),
            { removed: true }
        );
    }

    async function handleDeleteGroup() {
        await performAction(
            () => deleteGroup(conversationId),
            { removed: true }
        );
    }

    /* ==================================================
       CONFIRMATION
    ================================================== */

    function askConfirmation({
        title,
        description,
        action,
        confirmLabel = "CONFIRM",
    }) {
        setError("");

        setConfirmation({
            title,
            description,
            action,
            confirmLabel,
        });
    }

    async function executeConfirmation() {
        if (!confirmation || busy) return;

        const action = confirmation.action;

        await action();
    }

    /* ==================================================
       VALIDATION
    ================================================== */

    if (!conversationId) {
        return (
            <div style={styles.invalidOverlay}>
                <div style={styles.invalidPanel}>
                    <h3>Group unavailable</h3>
                    <p>The group information could not be loaded.</p>

                    <button
                        type="button"
                        onClick={onClose}
                        style={styles.invalidButton}
                    >
                        CLOSE
                    </button>
                </div>
            </div>
        );
    }

    /* ==================================================
       RENDER
    ================================================== */

    return (
        <div
            className="securex-group-overlay"
            onMouseDown={(event) => {
                if (
                    event.target === event.currentTarget &&
                    !busy &&
                    !confirmation
                ) {
                    onClose?.();
                }
            }}
        >
            <section
                className="securex-group-panel"
                role="dialog"
                aria-modal="true"
                aria-labelledby="securex-group-title"
            >
                <style>{`
                    .securex-group-overlay {
                        position: fixed;
                        inset: 0;
                        z-index: 100000;
                        display: grid;
                        place-items: center;
                        padding: 18px;
                        background: rgba(0,0,0,.76);
                        backdrop-filter: blur(8px);
                    }

                    .securex-group-panel {
                        width: min(100%, 480px);
                        max-height: min(85vh, 680px);
                        display: flex;
                        flex-direction: column;
                        overflow: hidden;
                        border: 1px solid rgba(255,75,95,.3);
                        border-radius: 16px;
                        background: #141418;
                        color: #eee;
                        box-shadow: 0 25px 80px rgba(0,0,0,.6);
                        animation: securexGroupAppear .18s ease;
                    }

                    @keyframes securexGroupAppear {
                        from {
                            opacity: 0;
                            transform: translateY(8px) scale(.985);
                        }
                        to {
                            opacity: 1;
                            transform: translateY(0) scale(1);
                        }
                    }

                    .securex-group-top {
                        display: flex;
                        align-items: center;
                        justify-content: space-between;
                        gap: 12px;
                        padding: 20px;
                        border-bottom: 1px solid rgba(255,255,255,.08);
                    }

                    .securex-group-heading {
                        display: flex;
                        align-items: center;
                        gap: 12px;
                        min-width: 0;
                    }

                    .securex-group-heading-icon {
                        width: 42px;
                        height: 42px;
                        display: grid;
                        place-items: center;
                        flex-shrink: 0;
                        border: 1px solid rgba(255,75,95,.3);
                        border-radius: 12px;
                        background: rgba(220,35,55,.12);
                        color: #ff687c;
                    }

                    .securex-group-heading h3 {
                        margin: 0;
                        overflow-wrap: anywhere;
                        font-size: 16px;
                        font-weight: 700;
                    }

                    .securex-group-heading small {
                        display: block;
                        margin-top: 5px;
                        color: #999;
                        font-size: 10px;
                        letter-spacing: 1px;
                    }

                    .securex-group-close {
                        width: 34px;
                        height: 34px;
                        display: grid;
                        place-items: center;
                        flex-shrink: 0;
                        border: 1px solid rgba(255,255,255,.1);
                        border-radius: 9px;
                        background: transparent;
                        color: #aaa;
                        cursor: pointer;
                    }

                    .securex-group-close:hover {
                        color: white;
                        background: rgba(255,255,255,.08);
                    }

                    .securex-group-content {
                        padding: 20px;
                        overflow-y: auto;
                        overscroll-behavior: contain;
                    }

                    .securex-group-section-title {
                        display: flex;
                        align-items: center;
                        justify-content: space-between;
                        gap: 10px;
                        margin-bottom: 12px;
                        color: #aaa;
                        font-size: 10px;
                        font-weight: 700;
                        letter-spacing: 1.1px;
                    }

                    .securex-group-count {
                        color: #ff8291;
                    }

                    .securex-group-member {
                        display: flex;
                        align-items: center;
                        gap: 11px;
                        min-height: 62px;
                        padding: 9px 0;
                        border-bottom: 1px solid rgba(255,255,255,.055);
                    }

                    .securex-group-member-avatar {
                        width: 39px;
                        height: 39px;
                        display: grid;
                        place-items: center;
                        flex-shrink: 0;
                        border: 1px solid rgba(255,75,95,.2);
                        border-radius: 50%;
                        background: rgba(220,35,55,.1);
                        color: #ff8291;
                    }

                    .securex-group-member-details {
                        min-width: 0;
                        flex: 1;
                    }

                    .securex-group-member-details strong {
                        display: block;
                        overflow: hidden;
                        color: #eee;
                        font-size: 12px;
                        text-overflow: ellipsis;
                        white-space: nowrap;
                    }

                    .securex-group-member-details small {
                        display: block;
                        margin-top: 4px;
                        overflow: hidden;
                        color: #85858d;
                        font-size: 10px;
                        text-overflow: ellipsis;
                        white-space: nowrap;
                    }

                    .securex-group-badge {
                        display: inline-flex;
                        align-items: center;
                        gap: 4px;
                        margin-top: 5px;
                        padding: 3px 6px;
                        border: 1px solid rgba(255,75,95,.2);
                        border-radius: 5px;
                        background: rgba(220,35,55,.1);
                        color: #ff8291;
                        font-size: 9px;
                    }

                    .securex-group-actions {
                        display: flex;
                        gap: 5px;
                        flex-shrink: 0;
                    }

                    .securex-group-action {
                        width: 31px;
                        height: 31px;
                        display: grid;
                        place-items: center;
                        border: 1px solid rgba(255,255,255,.1);
                        border-radius: 8px;
                        background: rgba(255,255,255,.035);
                        color: #aaa;
                        cursor: pointer;
                    }

                    .securex-group-action:hover {
                        border-color: rgba(255,75,95,.5);
                        background: rgba(220,35,55,.12);
                        color: #ff8291;
                    }

                    .securex-group-action:disabled {
                        opacity: .4;
                        cursor: not-allowed;
                    }

                    .securex-group-add {
                        width: 100%;
                        min-height: 42px;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        gap: 8px;
                        margin-top: 16px;
                        border: 1px solid rgba(255,75,95,.35);
                        border-radius: 9px;
                        background: rgba(220,35,55,.1);
                        color: #ff8291;
                        font-size: 11px;
                        font-weight: 700;
                        cursor: pointer;
                    }

                    .securex-group-add:hover {
                        background: rgba(220,35,55,.2);
                        color: white;
                    }

                    .securex-group-add:disabled {
                        opacity: .5;
                        cursor: not-allowed;
                    }

                    .securex-group-admin-info {
                        display: flex;
                        align-items: center;
                        gap: 9px;
                        margin-top: 17px;
                        padding: 12px;
                        border: 1px solid rgba(255,255,255,.07);
                        border-radius: 9px;
                        background: rgba(255,255,255,.025);
                        color: #aaa;
                        font-size: 11px;
                        overflow-wrap: anywhere;
                    }

                    .securex-group-danger-zone {
                        display: flex;
                        flex-direction: column;
                        gap: 9px;
                        margin-top: 22px;
                        padding-top: 17px;
                        border-top: 1px solid rgba(255,255,255,.08);
                    }

                    .securex-group-danger-button {
                        min-height: 41px;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        gap: 8px;
                        padding: 8px 12px;
                        border: 1px solid rgba(255,75,95,.25);
                        border-radius: 8px;
                        background: rgba(220,35,55,.07);
                        color: #ff8795;
                        font-size: 11px;
                        font-weight: 600;
                        cursor: pointer;
                    }

                    .securex-group-danger-button:hover {
                        border-color: rgba(255,75,95,.6);
                        background: rgba(220,35,55,.17);
                    }

                    .securex-group-danger-button:disabled {
                        opacity: .5;
                        cursor: not-allowed;
                    }

                    .securex-group-error {
                        margin: 0 20px 16px;
                        padding: 11px 12px;
                        border: 1px solid rgba(255,75,95,.3);
                        border-radius: 8px;
                        background: rgba(220,35,55,.1);
                        color: #ff8795;
                        font-size: 11px;
                        line-height: 1.5;
                        overflow-wrap: anywhere;
                    }

                    .securex-group-bottom {
                        padding: 12px 20px;
                        border-top: 1px solid rgba(255,255,255,.07);
                        color: #777;
                        font-size: 10px;
                        line-height: 1.5;
                    }

                    .securex-confirm-overlay {
                        position: fixed;
                        inset: 0;
                        z-index: 100001;
                        display: grid;
                        place-items: center;
                        padding: 18px;
                        background: rgba(0,0,0,.72);
                        backdrop-filter: blur(5px);
                    }

                    .securex-confirm-panel {
                        width: min(100%, 350px);
                        padding: 22px;
                        border: 1px solid rgba(255,75,95,.35);
                        border-radius: 14px;
                        background: #17171b;
                        color: #eee;
                        box-shadow: 0 20px 60px rgba(0,0,0,.6);
                    }

                    .securex-confirm-actions {
                        display: flex;
                        gap: 9px;
                        margin-top: 18px;
                    }

                    .securex-confirm-actions button {
                        flex: 1;
                    }

                    @media(max-width: 480px) {
                        .securex-group-overlay {
                            padding: 10px;
                        }

                        .securex-group-content {
                            padding: 15px;
                        }

                        .securex-group-top {
                            padding: 15px;
                        }

                        .securex-group-error {
                            margin-left: 15px;
                            margin-right: 15px;
                        }
                    }

                    @media(prefers-reduced-motion: reduce) {
                        .securex-group-panel {
                            animation: none;
                        }
                    }
                `}</style>

                {/* HEADER */}

                <header className="securex-group-top">
                    <div className="securex-group-heading">
                        <div className="securex-group-heading-icon">
                            <Icon name="users" size={21} />
                        </div>

                        <div>
                            <h3 id="securex-group-title">
                                {groupName}
                            </h3>

                            <small>GROUP MANAGEMENT</small>
                        </div>
                    </div>

                    <button
                        type="button"
                        className="securex-group-close"
                        onClick={onClose}
                        disabled={busy}
                        aria-label="Close group information"
                        title="Close"
                    >
                        <Icon name="close" />
                    </button>
                </header>

                {/* CONTENT */}

                <div className="securex-group-content">
                    <div className="securex-group-section-title">
                        <span>GROUP MEMBERS</span>

                        <span className="securex-group-count">
                            {participants.length} MEMBERS
                        </span>
                    </div>

                    {participants.length === 0 ? (
                        <div
                            style={{
                                padding: 25,
                                textAlign: "center",
                                color: "#888",
                                fontSize: 12,
                            }}
                        >
                            No group members found.
                        </div>
                    ) : (
                        participants.map((member, index) => {
                            const memberId = getParticipantId(member);
                            const memberName = getParticipantName(member);
                            const memberEmail = getParticipantEmail(member);

                            const isMemberAdmin = adminIds.includes(memberId);

                            const isSelf = Boolean(
                                currentId && memberId === currentId
                            );

                            return (
                                <div
                                    className="securex-group-member"
                                    key={memberId || memberEmail || index}
                                >
                                    <div className="securex-group-member-avatar">
                                        <Icon name="user" size={18} />
                                    </div>

                                    <div className="securex-group-member-details">
                                        <strong>
                                            {memberName}
                                            {isSelf ? " (You)" : ""}
                                        </strong>

                                        <small>{memberEmail}</small>

                                        {isMemberAdmin && (
                                            <span className="securex-group-badge">
                                                <Icon name="crown" size={11} />
                                                GROUP ADMIN
                                            </span>
                                        )}
                                    </div>

                                    {/* ADMIN CONTROLS */}

                                    {isAdmin && !isSelf && (
                                        <div className="securex-group-actions">
                                            {!isMemberAdmin ? (
                                                <>
                                                    <button
                                                        type="button"
                                                        className="securex-group-action"
                                                        title={`Promote ${memberName} to admin`}
                                                        aria-label={`Promote ${memberName} to admin`}
                                                        disabled={busy}
                                                        onClick={() =>
                                                            askConfirmation({
                                                                title: "Promote to admin?",
                                                                description: `${memberName} will receive permission to add members, remove members and manage group administrators.`,
                                                                action: () =>
                                                                    handlePromoteAdmin(member),
                                                                confirmLabel: "PROMOTE",
                                                            })
                                                        }
                                                    >
                                                        <Icon name="crown" size={15} />
                                                    </button>

                                                    <button
                                                        type="button"
                                                        className="securex-group-action"
                                                        title={`Remove ${memberName} from group`}
                                                        aria-label={`Remove ${memberName} from group`}
                                                        disabled={busy}
                                                        onClick={() =>
                                                            askConfirmation({
                                                                title: "Remove group member?",
                                                                description: `${memberName} will be removed from this group.`,
                                                                action: () =>
                                                                    handleRemoveMember(member),
                                                                confirmLabel: "REMOVE",
                                                            })
                                                        }
                                                    >
                                                        <Icon name="remove" size={16} />
                                                    </button>
                                                </>
                                            ) : (
                                                <button
                                                    type="button"
                                                    className="securex-group-action"
                                                    title={`Dismiss ${memberName} as admin`}
                                                    aria-label={`Dismiss ${memberName} as admin`}
                                                    disabled={busy || remainingAdminCount <= 1}
                                                    onClick={() =>
                                                        askConfirmation({
                                                            title: "Dismiss group admin?",
                                                            description: `${memberName} will lose admin privileges but will remain a member of this group.`,
                                                            action: () =>
                                                                handleDismissAdmin(member),
                                                            confirmLabel: "DISMISS ADMIN",
                                                        })
                                                    }
                                                >
                                                    <Icon name="shield" size={15} />
                                                </button>
                                            )}
                                        </div>
                                    )}
                                </div>
                            );
                        })
                    )}

                    {/* ADD MEMBERS */}

                    {isAdmin && (
                        <button
                            type="button"
                            className="securex-group-add"
                            onClick={onAddMembers}
                            disabled={busy || !onAddMembers}
                        >
                            <Icon name="plus" size={16} />
                            ADD MEMBERS
                        </button>
                    )}

                    {/* ADMIN INFORMATION */}

                    <div className="securex-group-admin-info">
                        <Icon name="shield" size={17} />

                        <span>
                            Group admin(s): <strong>{adminNames}</strong>
                        </span>
                    </div>

                    {/* ADMIN ACTIONS */}

                    <div className="securex-group-danger-zone">
                        {isAdmin && (
                            <>
                                <button
                                    type="button"
                                    className="securex-group-danger-button"
                                    onClick={() =>
                                        askConfirmation({
                                            title: "Resign as group admin?",
                                            description:
                                                "You will lose administrative privileges but remain a normal member of this group. Your ability to add or remove members will end.",
                                            confirmLabel: "RESIGN AS ADMIN",
                                            action: handleResignAdmin,
                                        })
                                    }
                                    disabled={busy || remainingAdminCount <= 1}
                                    title={
                                        remainingAdminCount <= 1
                                            ? "Promote another member before resigning."
                                            : "Resign as group admin"
                                    }
                                >
                                    <Icon name="resign" size={16} />
                                    RESIGN AS ADMIN
                                </button>

                                {remainingAdminCount <= 1 && (
                                    <small style={{ color: "#ff8795", fontSize: 10 }}>
                                        Promote another member to admin before resigning or leaving.
                                    </small>
                                )}

                                <button
                                    type="button"
                                    className="securex-group-danger-button"
                                    onClick={() =>
                                        askConfirmation({
                                            title: "Delete this group?",
                                            description:
                                                "Permanently delete this group and its conversation history? This action cannot be undone.",
                                            confirmLabel: "DELETE GROUP",
                                            action: handleDeleteGroup,
                                        })
                                    }
                                    disabled={busy}
                                >
                                    <Icon name="trash" size={16} />
                                    DELETE GROUP FOR EVERYONE
                                </button>
                            </>
                        )}

                        {(!isAdmin || remainingAdminCount > 1) && (
                            <button
                                type="button"
                                className="securex-group-danger-button"
                                onClick={() =>
                                    askConfirmation({
                                        title: "Leave this group?",
                                        description:
                                            "You will leave this group and will no longer receive its messages.",
                                        confirmLabel: "LEAVE GROUP",
                                        action: handleLeaveGroup,
                                    })
                                }
                                disabled={busy}
                            >
                                <Icon name="leave" size={16} />
                                LEAVE GROUP
                            </button>
                        )}
                    </div>
                </div>

                {/* ERROR */}

                {error && (
                    <div className="securex-group-error" role="alert">
                        {error}
                    </div>
                )}

                {/* FOOTER */}

                <footer className="securex-group-bottom">
                    {busy
                        ? "Processing group changes..."
                        : "Group membership and administrative actions are managed securely."}
                </footer>
            </section>

            {/* CONFIRMATION DIALOG */}

            {confirmation && (
                <div
                    className="securex-confirm-overlay"
                    onMouseDown={(event) => {
                        if (
                            event.target === event.currentTarget &&
                            !busy
                        ) {
                            setConfirmation(null);
                        }
                    }}
                >
                    <section
                        className="securex-confirm-panel"
                        role="alertdialog"
                        aria-modal="true"
                        aria-labelledby="securex-confirm-title"
                        aria-describedby="securex-confirm-description"
                    >
                        <h3
                            id="securex-confirm-title"
                            style={{
                                margin: "0 0 10px",
                                fontSize: 16,
                            }}
                        >
                            {confirmation.title}
                        </h3>

                        <p
                            id="securex-confirm-description"
                            style={{
                                color: "#aaa",
                                fontSize: 12,
                                lineHeight: 1.6,
                                margin: 0,
                            }}
                        >
                            {confirmation.description}
                        </p>

                        <div className="securex-confirm-actions">
                            <button
                                type="button"
                                className="securex-group-danger-button"
                                onClick={() => setConfirmation(null)}
                                disabled={busy}
                            >
                                CANCEL
                            </button>

                            <button
                                type="button"
                                className="securex-group-danger-button"
                                style={{
                                    background: "rgba(220,35,55,.2)",
                                }}
                                onClick={executeConfirmation}
                                disabled={busy}
                            >
                                {busy
                                    ? "PLEASE WAIT..."
                                    : confirmation.confirmLabel}
                            </button>
                        </div>
                    </section>
                </div>
            )}
        </div>
    );
}

/* ==================================================
   INVALID GROUP FALLBACK
================================================== */

const styles = {
    invalidOverlay: {
        position: "fixed",
        inset: 0,
        zIndex: 100000,
        display: "grid",
        placeItems: "center",
        padding: 18,
        background: "rgba(0,0,0,.8)",
    },

    invalidPanel: {
        width: "100%",
        maxWidth: 350,
        padding: 25,
        border: "1px solid #492027",
        borderRadius: 14,
        background: "#141418",
        color: "#eee",
        textAlign: "center",
    },

    invalidButton: {
        marginTop: 15,
        padding: "10px 20px",
        border: "1px solid #a92d3b",
        borderRadius: 8,
        background: "#481b24",
        color: "#fff",
        cursor: "pointer",
    },
};
