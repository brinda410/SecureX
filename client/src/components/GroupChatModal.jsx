import { useState } from "react";

import {
    createGroup,
    addGroupMember,
} from "../services/conversationService.js";

/* ==================================================
   VALIDATION HELPERS
================================================== */

const normalizeEmail = (email = "") =>
    String(email).trim().toLowerCase();

const isValidGmail = (email = "") =>
    /^[a-zA-Z0-9._%+-]+@gmail\.com$/i.test(email);

const getErrorMessage = (error) => {
    if (typeof error === "string") return error;

    if (typeof error?.message === "string") {
        return error.message;
    }

    if (typeof error?.response?.data?.message === "string") {
        return error.response.data.message;
    }

    return "Unable to complete the request. Please try again.";
};

const getParticipantEmail = (member) => {
    if (typeof member === "string") {
        return normalizeEmail(member);
    }

    return normalizeEmail(
        member?.email ||
        member?.user?.email ||
        ""
    );
};

/* ==================================================
   GROUP CHAT MODAL
================================================== */

export default function GroupChatModal({
    onClose,
    onCreated,
    conversation,
    onAdded,
}) {
    const isAddMode = Boolean(conversation);

    const [groupName, setGroupName] = useState("");
    const [memberInput, setMemberInput] = useState("");
    const [members, setMembers] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");
    const [success, setSuccess] = useState("");

    /* ==================================================
       ADD MEMBERS TO SELECTION
    ================================================== */

    const addMembers = () => {
        setError("");
        setSuccess("");

        const emails = [
            ...new Set(
                memberInput
                    .split(/[\n,;]+/)
                    .map(normalizeEmail)
                    .filter(Boolean)
            ),
        ];

        if (!emails.length) {
            setError("Enter at least one member's Gmail address.");
            return;
        }

        if (emails.some((email) => !isValidGmail(email))) {
            setError("Only valid Gmail addresses are allowed.");
            return;
        }

        const existingEmails = new Set(
            (conversation?.participants || []).map(
                getParticipantEmail
            ).filter(Boolean)
        );

        const alreadySelected = new Set(members);

        const newEmails = emails.filter(
            (email) =>
                !existingEmails.has(email) &&
                !alreadySelected.has(email)
        );

        if (newEmails.length !== emails.length) {
            setError(
                "Some users are already in the group or already selected."
            );
        }

        if (!newEmails.length) return;

        setMembers((previous) => [
            ...new Set([...previous, ...newEmails]),
        ]);

        setMemberInput("");
    };

    /* ==================================================
       REMOVE SELECTED MEMBER
    ================================================== */

    const removeMember = (email) => {
        setMembers((previous) =>
            previous.filter((item) => item !== email)
        );
    };

    /* ==================================================
       SUBMIT GROUP / ADD MEMBERS
    ================================================== */

    const handleSubmit = async (event) => {
        event.preventDefault();

        if (loading) return;

        setError("");
        setSuccess("");

        if (isAddMode && members.length === 0) {
            setError("Add at least one new member.");
            return;
        }

        if (!isAddMode && !groupName.trim()) {
            setError("Please enter a group name.");
            return;
        }

        if (!isAddMode && members.length === 0) {
            setError("Add at least one member.");
            return;
        }

        if (!isAddMode && groupName.trim().length > 60) {
            setError("Group name cannot exceed 60 characters.");
            return;
        }

        setLoading(true);

        try {
            /* CREATE NEW GROUP */

            if (!isAddMode) {
                const createdConversation = await createGroup(
                    groupName.trim(),
                    members
                );

                if (!createdConversation) {
                    throw new Error(
                        "The group could not be created."
                    );
                }

                onCreated?.(createdConversation);
                onClose?.();

                return;
            }

            /* ADD MEMBERS TO EXISTING GROUP */

            const conversationId =
                conversation?._id ||
                conversation?.id;

            if (!conversationId) {
                throw new Error("Group ID could not be found.");
            }

            let updatedConversation = conversation;
            const addedEmails = [];
            const failedEmails = [];

            for (const email of members) {
                try {
                    const result = await addGroupMember(
                        conversationId,
                        email
                    );

                    if (result?.conversation) {
                        updatedConversation = result.conversation;
                    }

                    addedEmails.push(email);
                } catch (err) {
                    failedEmails.push({
                        email,
                        message: getErrorMessage(err),
                    });
                }
            }

            /* SOME MEMBERS FAILED */

            if (failedEmails.length > 0) {
                if (addedEmails.length > 0) {
                    onAdded?.(updatedConversation);
                }

                if (addedEmails.length > 0) {
                    setSuccess(
                        `Successfully added ${addedEmails.length} member(s).`
                    );
                }

                const failedMessage = failedEmails
                    .map(
                        (item) =>
                            `${item.email}: ${item.message}`
                    )
                    .join(" | ");

                setError(
                    addedEmails.length > 0
                        ? `Some members could not be added: ${failedMessage}`
                        : `Could not add members: ${failedMessage}`
                );

                return;
            }

            /* ALL MEMBERS ADDED */

            setSuccess("Members added successfully!");

            onAdded?.(updatedConversation);

            setTimeout(() => {
                onClose?.();
            }, 700);

        } catch (err) {
            setError(getErrorMessage(err));
        } finally {
            setLoading(false);
        }
    };

    /* ==================================================
       MODAL UI
    ================================================== */

    return (
        <div
            style={styles.overlay}
            onMouseDown={(event) => {
                if (event.target === event.currentTarget) {
                    onClose?.();
                }
            }}
        >
            <div
                style={styles.modal}
                onMouseDown={(event) => event.stopPropagation()}
                role="dialog"
                aria-modal="true"
                aria-labelledby="group-modal-title"
            >
                {/* HEADER */}

                <div style={styles.header}>
                    <div>
                        <div style={styles.eyebrow}>
                            SECUREX / GROUPS
                        </div>

                        <h2
                            id="group-modal-title"
                            style={styles.title}
                        >
                            {isAddMode
                                ? "Add members"
                                : "Create a group"}
                        </h2>

                        <p style={styles.subtitle}>
                            {isAddMode
                                ? `Add people to ${
                                      conversation?.name ||
                                      conversation?.groupName ||
                                      "this group"
                                  }.`
                                : "Bring your conversations together securely."}
                        </p>
                    </div>

                    <button
                        type="button"
                        onClick={onClose}
                        style={styles.closeButton}
                        aria-label="Close"
                        title="Close"
                        disabled={loading}
                    >
                        ×
                    </button>
                </div>

                {/* FORM */}

                <form onSubmit={handleSubmit}>
                    {/* GROUP NAME */}

                    {!isAddMode && (
                        <>
                            <label
                                htmlFor="securex-group-name"
                                style={styles.label}
                            >
                                GROUP NAME
                            </label>

                            <input
                                id="securex-group-name"
                                type="text"
                                value={groupName}
                                onChange={(event) =>
                                    setGroupName(event.target.value)
                                }
                                placeholder="e.g. Project Team"
                                maxLength={60}
                                style={styles.input}
                                autoFocus
                                disabled={loading}
                            />
                        </>
                    )}

                    {/* MEMBER INPUT */}

                    <label
                        htmlFor="securex-member-email"
                        style={styles.label}
                    >
                        ADD MEMBERS
                    </label>

                    <div style={styles.memberInputRow}>
                        <input
                            id="securex-member-email"
                            type="text"
                            value={memberInput}
                            onChange={(event) =>
                                setMemberInput(event.target.value)
                            }
                            onKeyDown={(event) => {
                                if (event.key === "Enter") {
                                    event.preventDefault();
                                    addMembers();
                                }
                            }}
                            placeholder="Enter Gmail address"
                            style={styles.memberInput}
                            disabled={loading}
                        />

                        <button
                            type="button"
                            onClick={addMembers}
                            style={styles.addButton}
                            disabled={loading}
                        >
                            + Add
                        </button>
                    </div>

                    <p style={styles.hint}>
                        Enter Gmail addresses separated by commas,
                        semicolons or new lines.
                    </p>

                    {/* SELECTED MEMBERS */}

                    <div style={styles.membersHeading}>
                        <span>NEW MEMBERS</span>

                        <span style={styles.memberCount}>
                            {members.length}
                        </span>
                    </div>

                    <div style={styles.memberList}>
                        {members.length === 0 ? (
                            <div style={styles.emptyMembers}>
                                No new members selected.
                            </div>
                        ) : (
                            members.map((email) => (
                                <div
                                    key={email}
                                    style={styles.memberItem}
                                >
                                    <div style={styles.avatar}>
                                        {email.charAt(0).toUpperCase()}
                                    </div>

                                    <span style={styles.memberEmail}>
                                        {email}
                                    </span>

                                    <button
                                        type="button"
                                        onClick={() => removeMember(email)}
                                        style={styles.removeButton}
                                        title={`Remove ${email}`}
                                        aria-label={`Remove ${email}`}
                                        disabled={loading}
                                    >
                                        ×
                                    </button>
                                </div>
                            ))
                        )}
                    </div>

                    {/* ERROR MESSAGE */}

                    {error && (
                        <div
                            style={styles.error}
                            role="alert"
                        >
                            {error}
                        </div>
                    )}

                    {/* SUCCESS MESSAGE */}

                    {success && (
                        <div
                            style={styles.success}
                            role="status"
                        >
                            {success}
                        </div>
                    )}

                    {/* FOOTER */}

                    <div style={styles.footer}>
                        <button
                            type="button"
                            onClick={onClose}
                            style={styles.cancelButton}
                            disabled={loading}
                        >
                            Cancel
                        </button>

                        <button
                            type="submit"
                            style={{
                                ...styles.createButton,
                                opacity: loading ? 0.7 : 1,
                            }}
                            disabled={loading}
                        >
                            {loading
                                ? "Please wait..."
                                : isAddMode
                                    ? "Add members"
                                    : "Create group"}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}

/* ==================================================
   STYLES
================================================== */

const styles = {
    overlay: {
        position: "fixed",
        inset: 0,
        zIndex: 10000,
        background: "rgba(0, 0, 0, 0.78)",
        backdropFilter: "blur(7px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "18px",
    },

    modal: {
        width: "100%",
        maxWidth: "470px",
        maxHeight: "90vh",
        overflowY: "auto",
        background: "#111113",
        border: "1px solid #492027",
        borderRadius: "16px",
        padding: "26px",
        boxShadow: "0 20px 70px rgba(0,0,0,0.65)",
        color: "#f5f5f5",
        fontFamily: "inherit",
        boxSizing: "border-box",
    },

    header: {
        display: "flex",
        justifyContent: "space-between",
        alignItems: "flex-start",
        gap: "15px",
        marginBottom: "28px",
    },

    eyebrow: {
        color: "#ed424f",
        fontSize: "10px",
        fontWeight: 800,
        letterSpacing: "2px",
        marginBottom: "9px",
    },

    title: {
        fontSize: "24px",
        fontWeight: 750,
        margin: 0,
        color: "#fff",
    },

    subtitle: {
        color: "#929299",
        fontSize: "13px",
        marginTop: "8px",
        lineHeight: 1.5,
    },

    closeButton: {
        border: "none",
        background: "#242428",
        color: "#ddd",
        width: "32px",
        height: "32px",
        flexShrink: 0,
        borderRadius: "8px",
        fontSize: "23px",
        cursor: "pointer",
    },

    label: {
        display: "block",
        color: "#aaa",
        fontSize: "10px",
        fontWeight: 800,
        letterSpacing: "1.3px",
        marginBottom: "9px",
        marginTop: "20px",
    },

    input: {
        width: "100%",
        boxSizing: "border-box",
        padding: "13px 14px",
        borderRadius: "9px",
        border: "1px solid #38383e",
        background: "#19191d",
        color: "#fff",
        outline: "none",
        fontSize: "13px",
    },

    memberInputRow: {
        display: "flex",
        gap: "9px",
    },

    memberInput: {
        flex: 1,
        minWidth: 0,
        padding: "13px 14px",
        borderRadius: "9px",
        border: "1px solid #38383e",
        background: "#19191d",
        color: "#fff",
        outline: "none",
        fontSize: "13px",
        boxSizing: "border-box",
    },

    addButton: {
        padding: "0 19px",
        border: "1px solid #a92d3b",
        background: "#481b24",
        color: "#ffb6bd",
        borderRadius: "9px",
        cursor: "pointer",
        fontWeight: 700,
        flexShrink: 0,
    },

    hint: {
        color: "#77777f",
        fontSize: "11px",
        marginTop: "9px",
        lineHeight: 1.5,
    },

    membersHeading: {
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        color: "#aaa",
        fontSize: "10px",
        fontWeight: 800,
        letterSpacing: "1.2px",
        marginTop: "23px",
        marginBottom: "10px",
    },

    memberCount: {
        color: "#ff6875",
        background: "#3c1b22",
        borderRadius: "20px",
        padding: "4px 9px",
    },

    memberList: {
        maxHeight: "155px",
        overflowY: "auto",
        border: "1px solid #29292e",
        borderRadius: "9px",
        padding: "7px",
    },

    emptyMembers: {
        color: "#77777f",
        fontSize: "12px",
        textAlign: "center",
        padding: "20px 8px",
    },

    memberItem: {
        display: "flex",
        alignItems: "center",
        gap: "10px",
        padding: "8px",
        borderRadius: "7px",
    },

    avatar: {
        width: "30px",
        height: "30px",
        flexShrink: 0,
        borderRadius: "50%",
        background: "#49202a",
        color: "#ff9da7",
        display: "grid",
        placeItems: "center",
        fontSize: "12px",
        fontWeight: 800,
    },

    memberEmail: {
        flex: 1,
        minWidth: 0,
        overflow: "hidden",
        textOverflow: "ellipsis",
        whiteSpace: "nowrap",
        color: "#ddd",
        fontSize: "12px",
    },

    removeButton: {
        border: "none",
        background: "transparent",
        color: "#ff6875",
        fontSize: "20px",
        cursor: "pointer",
        flexShrink: 0,
    },

    error: {
        marginTop: "15px",
        padding: "10px 12px",
        background: "#35171c",
        border: "1px solid #762c38",
        borderRadius: "8px",
        color: "#ff9ca6",
        fontSize: "12px",
        lineHeight: 1.5,
        overflowWrap: "anywhere",
    },

    success: {
        marginTop: "15px",
        padding: "10px 12px",
        background: "#153324",
        border: "1px solid #286c48",
        borderRadius: "8px",
        color: "#8df0b4",
        fontSize: "12px",
    },

    footer: {
        display: "flex",
        justifyContent: "flex-end",
        gap: "10px",
        marginTop: "25px",
    },

    cancelButton: {
        padding: "11px 17px",
        borderRadius: "8px",
        border: "1px solid #38383e",
        background: "#202024",
        color: "#ddd",
        cursor: "pointer",
        fontWeight: 600,
    },

    createButton: {
        padding: "11px 19px",
        borderRadius: "8px",
        border: "1px solid #d43b4b",
        background: "#b52d3d",
        color: "#fff",
        cursor: "pointer",
        fontWeight: 750,
    },
};