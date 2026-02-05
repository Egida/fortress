"use client";

import { useState } from "react";

interface CountryFlagProps {
  code: string | undefined | null;
  size?: number;
  className?: string;
}

/**
 * Renders a country flag as an image using flagcdn.com.
 * Falls back to a styled country code badge if the image fails to load.
 */
export function CountryFlag({ code, size = 20, className = "" }: CountryFlagProps) {
  const [error, setError] = useState(false);

  if (!code || code.length !== 2) {
    return null;
  }

  const lower = code.toLowerCase();
  const height = Math.round(size * 0.75);

  if (error) {
    return (
      <span
        className={`inline-flex items-center justify-center rounded text-[10px] font-bold leading-none bg-zinc-700 text-zinc-300 ${className}`}
        style={{ width: size, height, fontSize: Math.max(8, size * 0.4) }}
        title={code.toUpperCase()}
      >
        {code.toUpperCase()}
      </span>
    );
  }

  return (
    <img
      src={`https://flagcdn.com/w${size * 2}/${lower}.png`}
      srcSet={`https://flagcdn.com/w${size * 2}/${lower}.png 1x, https://flagcdn.com/w${size * 3}/${lower}.png 2x`}
      alt={code.toUpperCase()}
      title={code.toUpperCase()}
      width={size}
      height={height}
      className={`inline-block rounded-[2px] object-cover ${className}`}
      style={{ width: size, height }}
      onError={() => setError(true)}
      loading="lazy"
    />
  );
}
