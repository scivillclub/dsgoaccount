"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import { Eye, EyeOff, LogIn, Sparkles, ChevronRight, ChevronLeft, Check, Mail, Loader2 } from "lucide-react";
import { useApp } from "@/context/AppContext";

type Tab = "login" | "register";
type RegStep = 1 | 2 | 3 | 4;

const TERMS_TEXT = `제1조 (목적)
이 약관은 Scivill(이하 "동아리")이 제공하는 서비스(이하 "서비스")의 이용조건 및 절차, 동아리와 회원 간의 권리, 의무 및 책임사항을 규정함을 목적으로 합니다.

제2조 (서비스 이용)
① 서비스는 Scivill 동아리 회원 및 허가된 사용자에게 제공됩니다.
② 회원은 서비스 이용 시 관련 법령, 이 약관의 규정, 동아리의 정책 등을 준수하여야 합니다.
③ 회원은 타인의 개인정보, 계정 정보를 무단으로 수집·이용하거나 제3자에게 제공해서는 안 됩니다.

제3조 (계정 및 보안)
① 회원은 자신의 계정 정보(아이디, 비밀번호 등)를 안전하게 관리할 책임이 있습니다.
② 회원의 계정 관리 소홀, 부정 사용에 의하여 발생하는 모든 결과에 대한 책임은 회원에게 있습니다.
③ 타인의 정보를 도용하여 서비스를 이용하는 행위는 금지됩니다.

제4조 (서비스의 변경 및 중지)
동아리는 운영상, 기술상의 이유로 서비스의 전부 또는 일부를 변경하거나 중지할 수 있습니다.

제5조 (면책 조항)
동아리는 회원이 서비스를 이용하여 기대하는 이익을 얻지 못하거나 상실한 것에 대하여 책임을 지지 않습니다.

제6조 (약관의 효력 및 변경)
이 약관은 서비스 화면에 게시하거나 기타 방법으로 회원에게 공지함으로써 효력이 발생합니다.`;

const PRIVACY_TEXT = `Scivill(이하 "동아리")은 개인정보보호법에 따라 회원의 개인정보를 아래와 같이 처리합니다.

■ 수집하는 개인정보 항목
이름, 학번, 이메일 주소, 아이디, 비밀번호(암호화 저장)

■ 개인정보의 수집·이용 목적
- 회원 가입 및 관리
- 서비스 제공 및 운영
- 이메일 인증 코드 발송

■ 개인정보의 보유·이용 기간
회원 탈퇴 시 즉시 파기. 단 관계 법령에 따라 보존이 필요한 경우 해당 기간 동안 보관합니다.

■ 개인정보의 제3자 제공
동아리는 회원의 개인정보를 원칙적으로 외부에 제공하지 않습니다. 다만, 회원이 사전에 동의한 경우 또는 법령의 규정에 의한 경우에는 예외로 합니다.

■ 개인정보 처리 위탁
동아리는 서비스 운영을 위해 아래와 같이 개인정보 처리 업무를 위탁할 수 있습니다.
- Firebase (Google LLC): 데이터 저장 및 인증

■ 정보주체의 권리
회원은 언제든지 자신의 개인정보 열람, 정정, 삭제, 처리 정지를 요청할 수 있습니다.`;

export default function AuthPage() {
  const { currentUser, login, registerUser, pushToast } = useApp();
  const router = useRouter();
  const [tab, setTab] = useState<Tab>("login");
  const [loading, setLoading] = useState(false);
  const [showPw, setShowPw] = useState(false);
  const [redirectUri, setRedirectUri] = useState<string | null>(null);

  // 로그인 폼
  const [loginId, setLoginId] = useState("");
  const [loginPw, setLoginPw] = useState("");
  const [remember, setRemember] = useState(false);

  // 회원가입 스텝
  const [step, setStep] = useState<RegStep>(1);
  // Step 1
  const [agreeTerms, setAgreeTerms] = useState(false);
  const [agreePrivacy, setAgreePrivacy] = useState(false);
  // Step 2
  const [regName, setRegName] = useState("");
  const [regStudentId, setRegStudentId] = useState("");
  // Step 3
  const [regEmail, setRegEmail] = useState("");
  const [codeSent, setCodeSent] = useState(false);
  const [emailCode, setEmailCode] = useState("");
  const [emailVerified, setEmailVerified] = useState(false);
  const [sendingCode, setSendingCode] = useState(false);
  const [verifyingCode, setVerifyingCode] = useState(false);
  const [oauthMethod, setOauthMethod] = useState<"none" | "google" | "microsoft">("none");
  // Step 4
  const [regId, setRegId] = useState("");
  const [regPw, setRegPw] = useState("");
  const [regPw2, setRegPw2] = useState("");
  const [showRegPw, setShowRegPw] = useState(false);
  const [showRegPw2, setShowRegPw2] = useState(false);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    setRedirectUri(params.get("redirect_uri"));
  }, []);

  const completeSSO = async (uri: string): Promise<boolean> => {
    try {
      const res = await fetch(`/api/auth/sso/issue?redirect_uri=${encodeURIComponent(uri)}`);
      if (!res.ok) return false;
      const data = await res.json();
      if (data.redirectUrl) {
        window.location.href = data.redirectUrl;
        return true;
      }
    } catch (e) {
      console.error("[sso] completeSSO failed", e);
    }
    return false;
  };

  useEffect(() => {
    if (!currentUser) return;
    if (redirectUri) {
      completeSSO(redirectUri).then((ok) => {
        if (!ok) router.replace("/");
      });
    } else {
      router.replace("/");
    }
  }, [currentUser, redirectUri, router]);

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    if (!loginId.trim() || !loginPw.trim()) return;
    setLoading(true);
    try {
      const ok = await login(loginId.trim(), loginPw, remember);
      if (ok && !redirectUri) router.push("/");
    } finally {
      setLoading(false);
    }
  }

  function handleTabChange(t: Tab) {
    setTab(t);
    if (t === "register") setStep(1);
  }

  async function sendCode() {
    if (!regEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(regEmail)) {
      pushToast("올바른 이메일을 입력해 주세요.", "error"); return;
    }
    setSendingCode(true);
    try {
      const res = await fetch("/api/auth/send-code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: regEmail }),
      });
      const data = await res.json();
      if (data.ok) {
        setCodeSent(true);
        pushToast(data.dev ? "개발 모드: 콘솔에서 코드를 확인하세요." : "인증 코드가 발송되었습니다.", "success");
      } else if (data.error === "too_many_attempts") {
        pushToast("잠시 후 다시 시도해 주세요.", "error");
      } else {
        pushToast("이메일 발송 실패. 잠시 후 다시 시도해 주세요.", "error");
      }
    } finally {
      setSendingCode(false);
    }
  }

  async function verifyCode() {
    if (!emailCode.trim()) return;
    setVerifyingCode(true);
    try {
      const res = await fetch("/api/auth/send-code", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: regEmail, code: emailCode }),
      });
      const data = await res.json();
      if (data.ok) {
        setEmailVerified(true);
        pushToast("이메일 인증 완료!", "success");
      } else if (data.error === "code_expired") {
        pushToast("인증 코드가 만료되었습니다. 재발송해 주세요.", "error");
        setCodeSent(false); setEmailCode("");
      } else if (data.error === "invalid_code") {
        pushToast("인증 코드가 올바르지 않습니다.", "error");
      } else {
        pushToast("인증 시도가 너무 많습니다. 재발송해 주세요.", "error");
        setCodeSent(false); setEmailCode("");
      }
    } finally {
      setVerifyingCode(false);
    }
  }

  async function handleRegister() {
    if (!regId.trim() || !regPw.trim()) return;
    if (regPw !== regPw2) { pushToast("비밀번호가 일치하지 않습니다.", "error"); return; }
    setLoading(true);
    try {
      const ok = await registerUser({
        username: regId.trim(),
        password: regPw,
        studentId: regStudentId.trim(),
        name: regName.trim(),
        email: oauthMethod !== "none" ? "" : regEmail,
      });
      if (ok && !redirectUri) router.push("/");
    } finally {
      setLoading(false);
    }
  }

  const allAgreed = agreeTerms && agreePrivacy;

  const stepLabels = ["약관동의", "기본정보", "이메일", "비밀번호"];

  return (
    <div className="min-h-screen flex items-center justify-center px-4 py-16">
      <div className="w-full max-w-sm">
        {/* 로고 */}
        <motion.div initial={{ opacity: 0, y: -16 }} animate={{ opacity: 1, y: 0 }}
          className="text-center mb-8">
          <div className="inline-flex items-center justify-center mb-3">
            <img src="/scivill-emblem.png" alt="Scivill"
              className="h-16 w-auto object-contain"
              style={{ filter: "brightness(1.3) contrast(1.1)" }} />
          </div>
          <h1 className="text-2xl font-black text-white">scivill</h1>
          <p className="text-xs text-slate-500 mt-1 flex items-center justify-center gap-1">
            <Sparkles size={10} /> 과학 × 개발 동아리
          </p>
        </motion.div>

        {/* 카드 */}
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="glass-card p-6">

          {/* 탭 */}
          <div className="flex rounded-xl p-1 mb-6" style={{ background: "rgba(255,255,255,0.04)" }}>
            {(["login", "register"] as Tab[]).map((t) => (
              <button key={t} onClick={() => handleTabChange(t)}
                className="flex-1 rounded-lg py-2 text-sm font-semibold transition-all"
                style={{
                  background: tab === t ? "rgba(99,102,241,0.2)" : "transparent",
                  color: tab === t ? "#818cf8" : "rgba(255,255,255,0.4)",
                  border: tab === t ? "1px solid rgba(99,102,241,0.3)" : "1px solid transparent",
                }}>
                {t === "login" ? "로그인" : "회원가입"}
              </button>
            ))}
          </div>

          <AnimatePresence mode="wait">
            {tab === "login" ? (
              <motion.form key="login"
                initial={{ opacity: 0, x: -16 }} animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 16 }} transition={{ duration: 0.2 }}
                onSubmit={handleLogin} className="space-y-4">
                <div>
                  <label className="text-xs font-semibold text-slate-400 mb-1.5 block uppercase tracking-wide">이메일 아이디</label>
                  <input type="text" value={loginId} onChange={(e) => setLoginId(e.target.value)}
                    placeholder="이메일 또는 아이디 입력" autoComplete="username" className="input-base" />
                </div>
                <div>
                  <label className="text-xs font-semibold text-slate-400 mb-1.5 block uppercase tracking-wide">비밀번호</label>
                  <div className="relative">
                    <input type={showPw ? "text" : "password"} value={loginPw} onChange={(e) => setLoginPw(e.target.value)}
                      placeholder="비밀번호 입력" autoComplete="current-password" className="input-base pr-10" />
                    <button type="button" onClick={() => setShowPw((p) => !p)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-white/30 hover:text-white/60 transition-colors">
                      {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                  </div>
                </div>
                <label className="flex items-center gap-2 cursor-pointer select-none">
                  <div onClick={() => setRemember(p => !p)}
                    className="relative flex items-center justify-center w-4 h-4 rounded transition-all shrink-0"
                    style={{
                      background: remember ? "rgba(99,102,241,0.8)" : "rgba(255,255,255,0.06)",
                      border: remember ? "1px solid rgba(99,102,241,0.8)" : "1px solid rgba(255,255,255,0.15)",
                    }}>
                    {remember && <svg width="10" height="8" viewBox="0 0 10 8" fill="none"><path d="M1 4l3 3 5-6" stroke="white" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                  </div>
                  <span className="text-xs" style={{ color: "rgba(255,255,255,0.45)" }}>로그인 상태 유지 (30일)</span>
                </label>
                <button type="submit" disabled={loading || !loginId || !loginPw}
                  suppressHydrationWarning
                  className="btn-primary w-full justify-center mt-2 disabled:opacity-50 disabled:cursor-not-allowed">
                  {loading ? <span className="animate-spin h-4 w-4 rounded-full border-2 border-white/20 border-t-white" />
                    : <><LogIn size={15} /> 로그인</>}
                </button>
                {/* ── 간편 로그인 ── */}
                <div>
                  <div className="flex items-center gap-3">
                    <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.08)" }} />
                    <span className="text-xs" style={{ color: "rgba(255,255,255,0.25)" }}>간편 로그인</span>
                    <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.08)" }} />
                  </div>
                  <div className="grid grid-cols-2 gap-2 mt-3">
                    <OAuthBtn onClick={() => window.location.href = "/api/auth/google"} bg="rgba(255,255,255,0.05)" border="rgba(255,255,255,0.12)" color="rgba(255,255,255,0.7)" icon={<svg width="14" height="14" viewBox="0 0 24 24"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>} label="Google" />
                    <OAuthBtn onClick={() => pushToast("Microsoft 로그인 연동은 준비 중입니다.", "info")} bg="rgba(255,255,255,0.05)" border="rgba(255,255,255,0.12)" color="rgba(255,255,255,0.7)" icon={<svg width="14" height="14" viewBox="0 0 21 21"><rect x="1" y="1" width="9" height="9" fill="#F25022"/><rect x="11" y="1" width="9" height="9" fill="#7FBA00"/><rect x="1" y="11" width="9" height="9" fill="#00A4EF"/><rect x="11" y="11" width="9" height="9" fill="#FFB900"/></svg>} label="Microsoft" />
                    <OAuthBtn onClick={() => pushToast("카카오 로그인 연동은 준비 중입니다.", "info")} bg="rgba(254,229,0,0.12)" border="rgba(254,229,0,0.25)" color="#ffe000" icon={<svg width="15" height="15" viewBox="0 0 24 24" fill="#ffe000"><path d="M12 3C6.477 3 2 6.477 2 10.8c0 2.7 1.632 5.08 4.11 6.48L5.07 21l4.56-2.52c.76.12 1.55.18 2.37.18 5.523 0 10-3.477 10-7.8S17.523 3 12 3z"/></svg>} label="카카오" />
                    <OAuthBtn onClick={() => pushToast("네이버 로그인 연동은 준비 중입니다.", "info")} bg="rgba(3,199,90,0.1)" border="rgba(3,199,90,0.25)" color="#03c75a" icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="#03c75a"><path d="M16.273 12.845L7.376 0H0v24h7.727V11.155L16.624 24H24V0h-7.727z"/></svg>} label="네이버" />
                    <OAuthBtn onClick={() => pushToast("Discord 로그인 연동은 준비 중입니다.", "info")} bg="rgba(88,101,242,0.12)" border="rgba(88,101,242,0.3)" color="#7983f5" icon={<svg width="15" height="15" viewBox="0 0 24 24" fill="#7983f5"><path d="M20.317 4.37a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.617-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 00-.041-.106 13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 01.078.01c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.299 12.299 0 01-1.873.892.077.077 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/></svg>} label="Discord" />
                    <OAuthBtn onClick={() => pushToast("GitHub 로그인 연동은 준비 중입니다.", "info")} bg="rgba(255,255,255,0.05)" border="rgba(255,255,255,0.12)" color="rgba(255,255,255,0.65)" icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0112 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/></svg>} label="GitHub" />
                  </div>
                </div>
              </motion.form>
            ) : (
              <motion.div key="register"
                initial={{ opacity: 0, x: 16 }} animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -16 }} transition={{ duration: 0.2 }}>

                {/* 스텝 인디케이터 */}
                <div className="flex items-center justify-between mb-6">
                  {stepLabels.map((label, i) => {
                    const n = (i + 1) as RegStep;
                    const done = step > n;
                    const active = step === n;
                    return (
                      <div key={n} className="flex flex-col items-center gap-1" style={{ flex: 1 }}>
                        <div className="flex items-center w-full">
                          {i > 0 && (
                            <div style={{
                              flex: 1, height: 2,
                              background: done || active ? "rgba(99,102,241,0.6)" : "rgba(255,255,255,0.08)"
                            }} />
                          )}
                          <div style={{
                            width: 26, height: 26, borderRadius: "50%", flexShrink: 0,
                            display: "flex", alignItems: "center", justifyContent: "center",
                            fontSize: 11, fontWeight: 700,
                            background: done ? "#6366f1" : active ? "rgba(99,102,241,0.25)" : "rgba(255,255,255,0.06)",
                            border: active ? "1.5px solid #6366f1" : done ? "none" : "1.5px solid rgba(255,255,255,0.12)",
                            color: done || active ? "#fff" : "rgba(255,255,255,0.3)",
                          }}>
                            {done ? <Check size={12} /> : n}
                          </div>
                          {i < stepLabels.length - 1 && (
                            <div style={{
                              flex: 1, height: 2,
                              background: done ? "rgba(99,102,241,0.6)" : "rgba(255,255,255,0.08)"
                            }} />
                          )}
                        </div>
                        <span style={{ fontSize: 10, color: active ? "#818cf8" : done ? "rgba(255,255,255,0.4)" : "rgba(255,255,255,0.2)" }}>
                          {label}
                        </span>
                      </div>
                    );
                  })}
                </div>

                <AnimatePresence mode="wait">
                  {/* ── STEP 1: 약관 동의 ─────────────────────────────────── */}
                  {step === 1 && (
                    <motion.div key="s1"
                      initial={{ opacity: 0, x: 16 }} animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0, x: -16 }} transition={{ duration: 0.18 }}
                      className="space-y-3">
                      <div>
                        <label className="text-xs font-semibold text-slate-400 mb-1.5 block uppercase tracking-wide">이용약관</label>
                        <div className="rounded-lg p-3 text-xs overflow-y-auto"
                          style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)", height: 120, color: "rgba(255,255,255,0.4)", whiteSpace: "pre-wrap", lineHeight: 1.7 }}>
                          {TERMS_TEXT}
                        </div>
                      </div>
                      <div>
                        <label className="text-xs font-semibold text-slate-400 mb-1.5 block uppercase tracking-wide">개인정보 처리방침</label>
                        <div className="rounded-lg p-3 text-xs overflow-y-auto"
                          style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)", height: 120, color: "rgba(255,255,255,0.4)", whiteSpace: "pre-wrap", lineHeight: 1.7 }}>
                          {PRIVACY_TEXT}
                        </div>
                      </div>
                      <label className="flex items-center gap-2 cursor-pointer select-none"
                        onClick={() => { setAgreeTerms(!allAgreed); setAgreePrivacy(!allAgreed); }}>
                        <Checkbox checked={allAgreed} />
                        <span className="text-xs font-semibold" style={{ color: "rgba(255,255,255,0.6)" }}>전체 동의</span>
                      </label>
                      <label className="flex items-center gap-2 cursor-pointer select-none" onClick={() => setAgreeTerms(p => !p)}>
                        <Checkbox checked={agreeTerms} small />
                        <span className="text-xs" style={{ color: "rgba(255,255,255,0.4)" }}>[필수] 이용약관 동의</span>
                      </label>
                      <label className="flex items-center gap-2 cursor-pointer select-none" onClick={() => setAgreePrivacy(p => !p)}>
                        <Checkbox checked={agreePrivacy} small />
                        <span className="text-xs" style={{ color: "rgba(255,255,255,0.4)" }}>[필수] 개인정보 처리방침 동의</span>
                      </label>
                      <button onClick={() => setStep(2)} disabled={!allAgreed}
                        className="btn-primary w-full justify-center disabled:opacity-30 disabled:cursor-not-allowed">
                        다음 <ChevronRight size={14} />
                      </button>
                    </motion.div>
                  )}

                  {/* ── STEP 2: 기본 정보 ─────────────────────────────────── */}
                  {step === 2 && (
                    <motion.div key="s2"
                      initial={{ opacity: 0, x: 16 }} animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0, x: -16 }} transition={{ duration: 0.18 }}
                      className="space-y-4">
                      <div>
                        <label className="text-xs font-semibold text-slate-400 mb-1.5 block uppercase tracking-wide">이름</label>
                        <input type="text" value={regName} onChange={(e) => setRegName(e.target.value)}
                          placeholder="홍길동" autoFocus className="input-base" />
                      </div>
                      <div>
                        <label className="text-xs font-semibold text-slate-400 mb-1.5 block uppercase tracking-wide">학번 (5자리)</label>
                        <input type="text" value={regStudentId} onChange={(e) => setRegStudentId(e.target.value.replace(/\D/g, "").slice(0, 5))}
                          placeholder="12345" inputMode="numeric" className="input-base" />
                      </div>
                      <div className="flex gap-2 mt-2">
                        <button onClick={() => setStep(1)}
                          className="flex-1 flex items-center justify-center gap-1 rounded-lg py-2 text-sm font-semibold transition-all"
                          style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", color: "rgba(255,255,255,0.4)" }}>
                          <ChevronLeft size={14} /> 이전
                        </button>
                        <button onClick={() => setStep(3)}
                          disabled={!regName.trim() || regStudentId.length !== 5}
                          className="flex-1 btn-primary justify-center disabled:opacity-30 disabled:cursor-not-allowed">
                          다음 <ChevronRight size={14} />
                        </button>
                      </div>
                    </motion.div>
                  )}

                  {/* ── STEP 3: 이메일 인증 ───────────────────────────────── */}
                  {step === 3 && (
                    <motion.div key="s3"
                      initial={{ opacity: 0, x: 16 }} animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0, x: -16 }} transition={{ duration: 0.18 }}
                      className="space-y-3">

                      {/* OAuth 버튼들 — 2열 그리드 */}
                      <div className="grid grid-cols-2 gap-2">
                        <OAuthBtn onClick={() => window.location.href = "/api/auth/google"}
                          bg="rgba(255,255,255,0.05)" border="rgba(255,255,255,0.12)" color="rgba(255,255,255,0.7)"
                          icon={<svg width="14" height="14" viewBox="0 0 24 24"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>}
                          label="Google" />
                        <OAuthBtn onClick={() => pushToast("Microsoft 로그인 연동은 준비 중입니다.", "info")}
                          bg="rgba(255,255,255,0.05)" border="rgba(255,255,255,0.12)" color="rgba(255,255,255,0.7)"
                          icon={<svg width="14" height="14" viewBox="0 0 21 21"><rect x="1" y="1" width="9" height="9" fill="#F25022"/><rect x="11" y="1" width="9" height="9" fill="#7FBA00"/><rect x="1" y="11" width="9" height="9" fill="#00A4EF"/><rect x="11" y="11" width="9" height="9" fill="#FFB900"/></svg>}
                          label="Microsoft" />
                        <OAuthBtn onClick={() => pushToast("카카오 로그인 연동은 준비 중입니다.", "info")}
                          bg="rgba(254,229,0,0.12)" border="rgba(254,229,0,0.25)" color="#ffe000"
                          icon={<svg width="15" height="15" viewBox="0 0 24 24" fill="#ffe000"><path d="M12 3C6.477 3 2 6.477 2 10.8c0 2.7 1.632 5.08 4.11 6.48L5.07 21l4.56-2.52c.76.12 1.55.18 2.37.18 5.523 0 10-3.477 10-7.8S17.523 3 12 3z"/></svg>}
                          label="카카오" />
                        <OAuthBtn onClick={() => pushToast("네이버 로그인 연동은 준비 중입니다.", "info")}
                          bg="rgba(3,199,90,0.1)" border="rgba(3,199,90,0.25)" color="#03c75a"
                          icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="#03c75a"><path d="M16.273 12.845L7.376 0H0v24h7.727V11.155L16.624 24H24V0h-7.727z"/></svg>}
                          label="네이버" />
                        <OAuthBtn onClick={() => pushToast("Discord 로그인 연동은 준비 중입니다.", "info")}
                          bg="rgba(88,101,242,0.12)" border="rgba(88,101,242,0.3)" color="#7983f5"
                          icon={<svg width="15" height="15" viewBox="0 0 24 24" fill="#7983f5"><path d="M20.317 4.37a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.617-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 00-.041-.106 13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 01.078.01c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.299 12.299 0 01-1.873.892.077.077 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/></svg>}
                          label="Discord" />
                        <OAuthBtn onClick={() => pushToast("GitHub 로그인 연동은 준비 중입니다.", "info")}
                          bg="rgba(255,255,255,0.05)" border="rgba(255,255,255,0.12)" color="rgba(255,255,255,0.65)"
                          icon={<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0112 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/></svg>}
                          label="GitHub" />
                      </div>

                      <div className="flex items-center gap-3">
                        <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.08)" }} />
                        <span className="text-xs" style={{ color: "rgba(255,255,255,0.25)" }}>직접 입력</span>
                        <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.08)" }} />
                      </div>

                      {/* 이메일 입력 */}
                      {!emailVerified ? (
                        <>
                          <div>
                            <label className="text-xs font-semibold text-slate-400 mb-1.5 block uppercase tracking-wide">이메일</label>
                            <div className="flex gap-2">
                              <input type="email" value={regEmail} onChange={(e) => { setRegEmail(e.target.value); setCodeSent(false); setEmailCode(""); }}
                                placeholder="scivill@example.com" className="input-base flex-1 min-w-0"
                                disabled={codeSent} />
                              <button type="button" onClick={sendCode} disabled={sendingCode || !regEmail}
                                className="shrink-0 flex items-center gap-1 rounded-lg px-3 text-xs font-semibold transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                                style={{ background: "rgba(99,102,241,0.2)", border: "1px solid rgba(99,102,241,0.4)", color: "#818cf8", whiteSpace: "nowrap" }}>
                                {sendingCode ? <Loader2 size={12} className="animate-spin" /> : <Mail size={12} />}
                                {codeSent ? "재발송" : "발송"}
                              </button>
                            </div>
                          </div>
                          {codeSent && (
                            <div>
                              <label className="text-xs font-semibold text-slate-400 mb-1.5 block uppercase tracking-wide">인증 코드 (6자리)</label>
                              <div className="flex gap-2">
                                <input type="text" value={emailCode} onChange={(e) => setEmailCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                                  placeholder="123456" inputMode="numeric" maxLength={6}
                                  className="input-base flex-1 min-w-0 tracking-widest text-center" />
                                <button type="button" onClick={verifyCode} disabled={verifyingCode || emailCode.length !== 6}
                                  className="shrink-0 flex items-center gap-1 rounded-lg px-3 text-xs font-semibold transition-all disabled:opacity-40"
                                  style={{ background: "rgba(52,211,153,0.15)", border: "1px solid rgba(52,211,153,0.3)", color: "#34d399", whiteSpace: "nowrap" }}>
                                  {verifyingCode ? <Loader2 size={12} className="animate-spin" /> : <Check size={12} />}
                                  확인
                                </button>
                              </div>
                              <p className="text-xs mt-1" style={{ color: "rgba(255,255,255,0.25)" }}>코드는 15분 후 만료됩니다</p>
                              <p className="text-xs mt-2" style={{ color: "rgba(255,180,0,0.7)" }}>⚠ 학교 이메일(@dshs.kr 등)은 인증 메일이 차단될 수 있습니다. 학교 이메일로 가입하시려면 위의 Google 빠른 로그인을 이용해 주세요.</p>
                              <p className="text-xs mt-1" style={{ color: "rgba(255,255,255,0.3)" }}>📬 메일이 안 보이면 스팸/정크 메일함을 확인해 주세요.</p>
                            </div>
                          )}
                        </>
                      ) : (
                        <div className="flex items-center gap-2 rounded-lg px-3 py-2.5"
                          style={{ background: "rgba(52,211,153,0.08)", border: "1px solid rgba(52,211,153,0.2)" }}>
                          <Check size={14} style={{ color: "#34d399", flexShrink: 0 }} />
                          <span className="text-xs" style={{ color: "#34d399" }}>{regEmail} 인증 완료</span>
                        </div>
                      )}

                      <div className="flex gap-2 mt-2">
                        <button onClick={() => setStep(2)}
                          className="flex-1 flex items-center justify-center gap-1 rounded-lg py-2 text-sm font-semibold transition-all"
                          style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", color: "rgba(255,255,255,0.4)" }}>
                          <ChevronLeft size={14} /> 이전
                        </button>
                        <button onClick={() => setStep(4)}
                          disabled={!emailVerified && oauthMethod === "none"}
                          className="flex-1 btn-primary justify-center disabled:opacity-30 disabled:cursor-not-allowed">
                          다음 <ChevronRight size={14} />
                        </button>
                      </div>
                    </motion.div>
                  )}

                  {/* ── STEP 4: 비밀번호 ──────────────────────────────────── */}
                  {step === 4 && (
                    <motion.div key="s4"
                      initial={{ opacity: 0, x: 16 }} animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0, x: -16 }} transition={{ duration: 0.18 }}
                      className="space-y-4">
                      <div>
                        <label className="text-xs font-semibold text-slate-400 mb-1.5 block uppercase tracking-wide">아이디</label>
                        <input type="text" value={regId} onChange={(e) => setRegId(e.target.value)}
                          placeholder="사용할 아이디" autoComplete="username" autoFocus className="input-base" />
                      </div>
                      <div>
                        <label className="text-xs font-semibold text-slate-400 mb-1.5 block uppercase tracking-wide">비밀번호</label>
                        <div className="relative">
                          <input type={showRegPw ? "text" : "password"} value={regPw} onChange={(e) => setRegPw(e.target.value)}
                            placeholder="6자 이상" autoComplete="new-password" className="input-base pr-10" />
                          <button type="button" onClick={() => setShowRegPw(p => !p)}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-white/30 hover:text-white/60">
                            {showRegPw ? <EyeOff size={16} /> : <Eye size={16} />}
                          </button>
                        </div>
                      </div>
                      <div>
                        <label className="text-xs font-semibold text-slate-400 mb-1.5 block uppercase tracking-wide">비밀번호 확인</label>
                        <div className="relative">
                          <input type={showRegPw2 ? "text" : "password"} value={regPw2} onChange={(e) => setRegPw2(e.target.value)}
                            placeholder="비밀번호 재입력" autoComplete="new-password" className="input-base pr-10"
                            style={{ borderColor: regPw2 && regPw !== regPw2 ? "rgba(244,63,94,0.5)" : undefined }} />
                          <button type="button" onClick={() => setShowRegPw2(p => !p)}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-white/30 hover:text-white/60">
                            {showRegPw2 ? <EyeOff size={16} /> : <Eye size={16} />}
                          </button>
                        </div>
                        {regPw2 && regPw !== regPw2 && (
                          <p className="text-xs mt-1" style={{ color: "#f87171" }}>비밀번호가 일치하지 않습니다</p>
                        )}
                      </div>
                      <div className="flex gap-2 mt-2">
                        <button onClick={() => setStep(3)}
                          className="flex-1 flex items-center justify-center gap-1 rounded-lg py-2 text-sm font-semibold transition-all"
                          style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", color: "rgba(255,255,255,0.4)" }}>
                          <ChevronLeft size={14} /> 이전
                        </button>
                        <button onClick={handleRegister}
                          disabled={loading || !regId.trim() || !regPw || regPw !== regPw2 || regPw.length < 6}
                          suppressHydrationWarning
                          className="flex-1 btn-primary justify-center disabled:opacity-30 disabled:cursor-not-allowed">
                          {loading ? <span className="animate-spin h-4 w-4 rounded-full border-2 border-white/20 border-t-white" />
                            : "가입하기"}
                        </button>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>
      </div>
    </div>
  );
}

function OAuthBtn({ onClick, bg, border, color, icon, label, className }: {
  onClick: () => void; bg: string; border: string; color: string;
  icon: React.ReactNode; label: string; className?: string;
}) {
  return (
    <button type="button" onClick={onClick}
      className={`flex items-center justify-center gap-1.5 rounded-lg py-2.5 text-xs font-semibold transition-all hover:opacity-80 ${className ?? ""}`}
      style={{ background: bg, border: `1px solid ${border}`, color }}>
      {icon}
      {label}
    </button>
  );
}

function Checkbox({ checked, small }: { checked: boolean; small?: boolean }) {
  const size = small ? 14 : 16;
  return (
    <div style={{
      width: size, height: size, borderRadius: 4, flexShrink: 0,
      display: "flex", alignItems: "center", justifyContent: "center",
      background: checked ? "rgba(99,102,241,0.8)" : "rgba(255,255,255,0.06)",
      border: checked ? "1px solid rgba(99,102,241,0.8)" : "1px solid rgba(255,255,255,0.15)",
      transition: "all 0.15s",
    }}>
      {checked && <svg width={small ? 8 : 10} height={small ? 6 : 8} viewBox="0 0 10 8" fill="none">
        <path d="M1 4l3 3 5-6" stroke="white" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
      </svg>}
    </div>
  );
}
