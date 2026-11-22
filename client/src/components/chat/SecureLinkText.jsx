import { useMemo } from "react";

import {
  LinkIcon,
  getLinkParts,
} from "../../utils/chatHelpers.jsx";

export default function SecureLinkText({ text = "" }) {
  const parts = useMemo(
    () => getLinkParts(text),
    [text]
  );

  return (
    <span className="securex-link-text">
      {parts.map((part, index) => {
        if (part.type === "text") {
          return (
            <span key={index}>
              {part.value}
            </span>
          );
        }

        return (
          <span
            className="securex-link-wrapper"
            key={index}
          >
            <a
              href={part.url}
              target="_blank"
              rel="noopener noreferrer nofollow"
              title={
                part.suspicious
                  ? "Warning: This link may be suspicious"
                  : `Open ${part.hostname}`
              }
            >
              {part.value}
            </a>

            {part.suspicious && (
              <span
                className="securex-link-warning"
                title="This URL has characteristics that may be suspicious. Verify it before opening."
              >
                ⚠ Verify link
              </span>
            )}

            <span className="securex-link-preview">
              <LinkIcon size={16} />

              <span>
                <strong>{part.hostname}</strong>

                <small>
                  {part.suspicious
                    ? "Check this destination before opening"
                    : "External website"}
                </small>
              </span>
            </span>
          </span>
        );
      })}
    </span>
  );
}