import { createContext, useCallback, useContext, useState, ReactNode } from "react";

export type Lang = "ja" | "en";

interface LangCtx {
  lang: Lang;
  setLang: (l: Lang) => void;
  t: (ja: string, en: string) => string;
}

const Ctx = createContext<LangCtx>({ lang: "ja", setLang: () => {}, t: (ja) => ja });

export function LangProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(() => {
    try { return (localStorage.getItem("lang") as Lang) || "ja"; } catch { return "ja"; }
  });
  const setLang = useCallback((l: Lang) => {
    setLangState(l);
    try { localStorage.setItem("lang", l); } catch { /* ignore */ }
  }, []);
  const t = useCallback((ja: string, en: string) => (lang === "en" ? en : ja), [lang]);
  return <Ctx.Provider value={{ lang, setLang, t }}>{children}</Ctx.Provider>;
}

export function useT() { return useContext(Ctx).t; }
export function useLang() { const c = useContext(Ctx); return { lang: c.lang, setLang: c.setLang }; }
