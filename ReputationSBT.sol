<!-- 🌌 GAMIFIED PEACE PROTOCOL — SMART CONTRACT PROFILE -->
<div align="center" style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
background:radial-gradient(800px 400px at 50% 20%,#101832 0%,#0b0f1a 60%,#070a11 100%);
padding:40px 20px;border-radius:20px;box-shadow:0 0 40px rgba(122,162,255,.15);overflow:hidden;position:relative;">

  <style>
    @keyframes gradientShift {
      0%{background-position:0% 50%}
      50%{background-position:100% 50%}
      100%{background-position:0% 50%}
    }
    @keyframes floatOrb {
      0%,100%{transform:translate(-50%,-50%) scale(1)}
      50%{transform:translate(-48%,-52%) scale(1.3)}
    }
    .animated-title {
      background:linear-gradient(90deg,#7aa2ff,#5ee1a0,#ffd36a,#7aa2ff);
      background-size:300% 300%;
      -webkit-background-clip:text;
      -webkit-text-fill-color:transparent;
      animation:gradientShift 6s ease infinite;
      font-weight:800;
      font-size:clamp(26px,5vw,44px);
      letter-spacing:.06em;
      margin:0 0 6px;
      text-transform:uppercase;
    }
    .orb {
      content:"";
      position:absolute;
      top:50%;left:50%;
      width:500px;height:500px;
      border-radius:50%;
      background:radial-gradient(circle at center,rgba(122,162,255,.25) 0%,transparent 70%);
      filter:blur(80px);
      animation:floatOrb 10s ease-in-out infinite;
      z-index:0;
    }
    .desc {
      color:#a8b7e8;
      font-size:clamp(14px,2vw,17px);
      max-width:680px;
      margin:0 auto;
      line-height:1.6;
      position:relative;
      z-index:1;
    }
    .pill {
      display:inline-block;
      margin-top:18px;
      padding:6px 12px;
      border-radius:999px;
      border:1px solid rgba(255,255,255,.15);
      background:rgba(255,255,255,.06);
      color:#cfe1ff;
      font-size:13px;
      letter-spacing:.05em;
    }
  </style>

  <div class="orb"></div>
  <h1 class="animated-title">Gamified Peace Protocol</h1>
  <p class="desc">
    A 35-contract, integrity-guarded suite that gamifies peacebuilding and verified humanitarian impact.  
    Each module—PeaceToken, ReputationSBT, QuestEscrow, Verifier, SeasonEngine—turns cooperation into XP, reputation, and real ETH rewards,  
    secured by Anti-Inversion Guards and dual-hash provenance.
  </p>
  <div class="pill">Integrity • Reputation • Impact • ETH Rewards</div>
</div>
