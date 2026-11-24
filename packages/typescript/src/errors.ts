/** Errors raised inside the tested process. Their messages never carry argument values. */

/**
 * A tool call was stopped before the original function ran: running it for real would be
 * unsafe, or the run's session cannot be trusted. `reason` is a short code that also goes to
 * the call log.
 */
export class GazuaBlockedError extends Error {
  readonly reason: string;
  readonly detail: string | undefined;

  constructor(reason: string, detail?: string) {
    super(`Gazua blocked this tool call (${detail === undefined ? reason : `${reason}: ${detail}`}).`);
    this.name = "GazuaBlockedError";
    this.reason = reason;
    this.detail = detail;
  }
}

/** `wrap` or `tool` received something that cannot become a tool inside a run. */
export class UnsupportedToolError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = "UnsupportedToolError";
  }
}
