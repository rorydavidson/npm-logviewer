/** The app mark: an NPM-inspired rounded badge with a proxy chevron and
 * analytics bars. Used in the header and on the login screen. */
export function LogoMark({ size = 28 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <defs>
        <linearGradient
          id="lvbg"
          x1="0"
          y1="0"
          x2="64"
          y2="64"
          gradientUnits="userSpaceOnUse"
        >
          <stop stopColor="#0d9488" />
          <stop offset="1" stopColor="#0ea5e9" />
        </linearGradient>
      </defs>
      <rect x="2" y="2" width="60" height="60" rx="16" fill="url(#lvbg)" />
      <path
        d="M19 18 L29 32 L19 46"
        stroke="#ffffff"
        strokeWidth="5"
        strokeLinecap="round"
        strokeLinejoin="round"
        opacity="0.55"
        fill="none"
      />
      <rect x="33" y="36" width="6" height="10" rx="2" fill="#ffffff" />
      <rect x="42" y="28" width="6" height="18" rx="2" fill="#ffffff" />
      <rect x="51" y="20" width="6" height="26" rx="2" fill="#ffffff" opacity="0.9" />
    </svg>
  );
}

export function Logo() {
  return (
    <div className="flex items-center gap-2">
      <LogoMark size={26} />
      <span className="text-sm font-semibold tracking-wide text-white">
        Proxy<span className="text-teal-400">Logs</span>
      </span>
    </div>
  );
}
