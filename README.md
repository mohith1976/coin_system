# 💰 Coin-Based User Engagement & Community Platform

A **MERN-stack application** that gamifies user engagement with a **coin economy system**.  
Users earn coins by completing activities (referrals, daily check-ins, ad interactions, social participation), while **Admins control the coin economy** through a **dynamic pool and redemption system**.  

The platform also lays the foundation for a **developer collaboration & community network**, enabling users to connect, build, and grow together. 

-----

## 📂 Repositories

The project is split into two repositories:

  - **User Backend (API for Users)** → Powers user authentication, rewards, transactions, redemption, communites join/create, performing activites to earn and the leaderboard.
  - **Admin  (API for Admins)** → Controls the coin pool, redemptions, fraud detection, and economy balancing.

-----

 



## 🚀 Features

### 👤 User Side
- **Authentication** – Secure Email OTP login system.
- **Earning System**:
  - Daily login & streak bonuses.
  - Ad-watching rewards.
  - Referral system.
  - Event-based bonus rewards.
- **Gamification**:
  - Leaderboards for top earners.
  - Premium access unlockable with coins.
- **Wallet & Transactions**:
  - View coin balance and transaction history.
  - Redeem coins for real-world value.
- **Community Building** *(Future Scope)*:
  - Social activities incentivized by rewards.
  - Connect with users sharing similar interests.
  - Build and join online communities.

---

### 🛠️ Admin Side (Super Admin Dashboard)
The **Super Admin** has complete control over the system with both **manual overrides** and **automated balancing mechanisms**.

#### 📌 1. Pool System Management
- Generate or burn coins manually.
- Adjust issuance rates, set distribution caps.
- Freeze all pool operations in emergencies.
- **Automation**: Dynamic issuance, anti-inflation coin burn, automated alerts.

#### 📌 2. Redemption System Management
- Start/stop redemptions.
- Set redemption limits, minimum balances, monthly caps.
- Approve/reject or prioritize payouts for VIP users.
- **Automation**: Smart payout queue, dynamic coin-to-currency scaling.

#### 📌 3. Earning System Management
- Adjust earning rates for tasks.
- Modify login streaks, ad rewards, or special event bonuses.
- Pause/resume coin rewards.
- **Automation**: Smart reward boosts, anti-spam reward reduction.

#### 📌 4. Security & Fraud Prevention
- Suspend or unban users.
- Adjust fraud detection strictness.
- **Automation**: Detect suspicious activity (multi-accounting, spam, abnormal redemptions).

#### 📌 5. Monitoring & Notifications
- Real-time analytics for pool, redemptions, and user activity.
- Automated alerts for anomalies (low pool, redemption spikes, fraud).
- Payout logs and earnings reports.

#### 📌 6. Multi-Admin Role Management
- Create & assign admin roles with granular permissions.
- Override other admin actions.
- Tiered access control (e.g., redemption admins vs fraud admins).

---

## 🏗️ Tech Stack
- **Frontend**: React.js , Flutter 
- **Backend**: Node.js + Express  
- **Database**: MongoDB Atlas  
- **Deployment**: AWS (backend), Netlify/Vercel (frontend)  

---

-----

## ⚡ Getting Started

### Prerequisites

  - Node.js (\>= 16.x)
  - MongoDB Atlas (or local MongoDB)
  - AWS (for deployment)

### Installation

```bash
# Clone repo
git clone https://github.com/mohith1976/coin_system.git


# Install backend dependencies

npm install


```

### Running Locally

```bash
# Start backend

npm run dev

```

-----

## 🔮 Future Roadmap

  - Android app with the same features.
  - Community building features like groups, posts, and chats.
  - AI-powered interest matching to find collaborators and startup teams.
  - Enhanced fraud detection with Machine Learning anomaly detection.

-----

## 🤝 Contributing

Contributions, issues, and feature requests are welcome\! Feel free to fork this repo and submit a pull request.

-----

## 📧 Contact

  - **Author**: Mohith Nakka
  - **Email**: mohith.nakka1976@gmail.com
  - **GitHub**: https://github.com/mohith1976

-----

## ⭐ Acknowledgments

Special thanks to all open-source tools and frameworks that power this project.


