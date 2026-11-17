import type { SvgComponent } from "astro/types"
import GitHub from "@/assets/icons/github.svg"
import RSS from "@/assets/icons/rss.svg"
import Twitter from "@/assets/icons/twitter.svg"

export const SITE = {
  title: "four0four",
  description:
    "Security research, CTF writeups, and notes on offensive security by Ameen Uddin Sheikh.",
  locale: "en-US",
  dir: "ltr",
  defaultPageImage: "/images/social-card.png",
  defaultPostImage: "/images/social-card.png",
} as const

export const AUTHOR = {
  name: "Ameen Uddin Sheikh",
  handle: "four0four",
  avatar: "/images/profile.jpg",
  url: "https://github.com/f0ur0four",
  twitter: "@f0ur0four",
} as const

export const NAVIGATION = [
  { href: "/blog", label: "Blog" },
  { href: "/about", label: "About" },
  { href: "/tags", label: "Tags" },
]

export const SOCIALS: { href: string; label: string; icon: SvgComponent }[] = [
  { href: AUTHOR.url, label: "GitHub", icon: GitHub },
  { href: "https://twitter.com/f0ur0four", label: "Twitter", icon: Twitter },
  { href: "/rss.xml", label: "RSS", icon: RSS },
]
