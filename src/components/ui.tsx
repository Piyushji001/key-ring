import clsx from "clsx";
import { forwardRef } from "react";
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from "react";

/** Buttons say what happens when they are used. "Unlock", not "Submit". */
export function Button({
  variant = "primary",
  className,
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "ghost" | "danger";
}) {
  return (
    <button
      {...rest}
      className={clsx(
        "h-9 px-4 rounded-control text-base font-medium transition-colors duration-100",
        "disabled:opacity-40 disabled:cursor-not-allowed",
        variant === "primary" &&
          "bg-accent text-void hover:bg-accent-hi disabled:hover:bg-accent",
        variant === "ghost" &&
          "bg-transparent text-text-dim hover:text-text hover:bg-panel-hi",
        variant === "danger" && "bg-danger text-white hover:opacity-90",
        className,
      )}
    >
      {children}
    </button>
  );
}

/**
 * Credential values, hostnames and passwords are always monospace - it
 * genuinely helps read random strings (l vs 1 vs I).
 *
 * forwardRef because the unlock screen autofocuses this on mount.
 */
type InputProps = InputHTMLAttributes<HTMLInputElement> & {
  mono?: boolean;
  invalid?: boolean;
};

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  { mono = true, invalid = false, className, ...rest },
  ref,
) {
  return (
    <input
      ref={ref}
      {...rest}
      className={clsx(
        "w-full h-10 px-3 rounded-control bg-panel text-text",
        "border transition-colors duration-100",
        "focus:outline-none focus:border-accent",
        invalid ? "border-danger" : "border-edge hover:border-edge-strong",
        mono ? "font-data tracking-wide" : "font-ui",
        className,
      )}
    />
  );
});

/** This app teaches its own shortcuts constantly, so hints are everywhere. */
export function Kbd({ children }: { children: ReactNode }) {
  return (
    <kbd className="inline-block px-[5px] py-[2px] rounded-tag bg-panel-hi border border-edge font-data text-xs text-text-dim">
      {children}
    </kbd>
  );
}

export function Label({ children }: { children: ReactNode }) {
  return (
    <span className="block mb-2 text-sm text-text-dim font-ui">{children}</span>
  );
}

/**
 * Errors explain what happened and what to do about it. They do not apologise
 * and they are never vague - except for unlock failures, where vagueness is the
 * security property.
 */
export function ErrorNote({ children }: { children: ReactNode }) {
  return (
    <p
      role="alert"
      className="mt-3 text-sm text-danger font-ui"
      data-selectable
    >
      {children}
    </p>
  );
}

/** The permanent, un-softenable warning at vault creation. */
export function DangerBlock({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-panel border border-danger/60 bg-danger/[0.07] p-4 text-sm leading-relaxed text-text">
      {children}
    </div>
  );
}

/** Five segments, because the score is 0-4 and a bar implies false precision. */
export function StrengthMeter({ score, hint }: { score: number; hint: string }) {
  return (
    <div className="mt-2">
      <div className="flex gap-1" aria-hidden>
        {[0, 1, 2, 3, 4].map((i) => (
          <div
            key={i}
            className={clsx(
              "h-1 flex-1 rounded-full transition-colors duration-100",
              i < score ? "bg-accent" : "bg-edge",
            )}
          />
        ))}
      </div>
      <p className="mt-1.5 text-xs text-text-faint font-ui">{hint}</p>
    </div>
  );
}
