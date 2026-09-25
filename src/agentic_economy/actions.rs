use super::constants::{COMMISSION_LEVELS_BPS, DQN_CB_ACTIONS, DQN_TRADER_ACTIONS};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EconomyActionError { InvalidAction }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CbPolicy {
    pub commission_bps: u16,
    pub liquidity_mode: u8,
    pub rate_regime: u8,
    pub syna_policy: u8,
}

impl CbPolicy {
    pub fn decode(action: u8) -> Result<Self, EconomyActionError> {
        if action as usize >= DQN_CB_ACTIONS { return Err(EconomyActionError::InvalidAction); }
        let ci = action / 18;
        let rest = action % 18;
        let liquidity_mode = rest / 6;
        let rest2 = rest % 6;
        Ok(Self {
            commission_bps: COMMISSION_LEVELS_BPS[ci as usize],
            liquidity_mode,
            rate_regime: rest2 / 3,
            syna_policy: rest2 % 3,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TraderAction {
    Hold=0, SellWethOtc=1, BuyWethOtc=2, SellSynaOtc=3, BuySynaOtc=4, AcceptBest=5,
    AmmBuy=6, AmmSell=7, ExternalBuy=8, ExternalSell=9, LpSuAdd=10, LpSuOut=11,
    LpSwAdd=12, LpSwOut=13, LpWuAdd=14, LpWuOut=15, Lend=16, Borrow=17,
    PeerDeposit=18, CbDeposit=19, CbBorrow=20, InvestCb=21, SyntheticMint=22,
    SyntheticRepay=23, SyntheticBurn=24, RepayAll=25, ArbSu=26, ArbSw=27,
    ArbWu=28, OtcArb=29, ReinvestCb=30, CompoundLp=31,
}

impl TryFrom<u8> for TraderAction {
    type Error = EconomyActionError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        if v as usize >= DQN_TRADER_ACTIONS { return Err(EconomyActionError::InvalidAction); }
        let a = match v {
            0=>Self::Hold,1=>Self::SellWethOtc,2=>Self::BuyWethOtc,3=>Self::SellSynaOtc,
            4=>Self::BuySynaOtc,5=>Self::AcceptBest,6=>Self::AmmBuy,7=>Self::AmmSell,
            8=>Self::ExternalBuy,9=>Self::ExternalSell,10=>Self::LpSuAdd,11=>Self::LpSuOut,
            12=>Self::LpSwAdd,13=>Self::LpSwOut,14=>Self::LpWuAdd,15=>Self::LpWuOut,
            16=>Self::Lend,17=>Self::Borrow,18=>Self::PeerDeposit,19=>Self::CbDeposit,
            20=>Self::CbBorrow,21=>Self::InvestCb,22=>Self::SyntheticMint,23=>Self::SyntheticRepay,
            24=>Self::SyntheticBurn,25=>Self::RepayAll,26=>Self::ArbSu,27=>Self::ArbSw,
            28=>Self::ArbWu,29=>Self::OtcArb,30=>Self::ReinvestCb,31=>Self::CompoundLp,
            _=>unreachable!(),
        };
        Ok(a)
    }
}
