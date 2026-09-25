pub const SYNERGY_CHAIN_ID: u64 = 777_777;
pub const MODELED_BLOCK_TIME_SECS: u64 = 12;
pub const MICRO: i128 = 1_000_000;

pub const DQN_TRADERS: usize = 6;
pub const DQN_TRADER_STATE: usize = 20;
pub const DQN_TRADER_ACTIONS: usize = 32;
pub const DQN_CB_STATE: usize = 12;
pub const DQN_CB_ACTIONS: usize = 90;
pub const DQN_HIDDEN: usize = 64;
pub const DQN_REPLAY: usize = 20_000;
pub const DQN_BATCH: usize = 48;
pub const DQN_TARGET_SYNC: usize = 500;
pub const DQN_UPDATE_EVERY: usize = 4;
pub const DQN_GAMMA_PPM: u32 = 990_000;

pub const AMM_FEE_BPS: u16 = 30;
pub const EXTERNAL_FEE_BPS: u16 = 10;
pub const AGENT_COLLATERAL_BPS: u16 = 15_000;
pub const CB_COLLATERAL_BPS: u16 = 13_000;
pub const CB_MINT_BPS: u16 = 200;
pub const CB_MINT_LIMIT: u8 = 5;
pub const COMMISSION_LEVELS_BPS: [u16; 5] = [0, 10, 30, 60, 100];
pub const RATE_REGIMES_BPS: [(u16, u16); 3] = [(200, 300), (800, 1_000), (1_800, 2_500)];

pub const GAS_MIN_INTERVAL_BLOCKS: u64 = 6;
pub const GAS_SAFETY_PPM: u32 = 1_500_000;
pub const GAS_BASE_UNITS: u64 = 90_000;
pub const GAS_UNITS_PER_LEG: u64 = 33_000;
pub const GAS_BASE_FEE_WEI: u64 = 5_000_000;
pub const GAS_L1_FACTOR_PPM: u32 = 1_300_000;
pub const GAS_MIN_NOTIONAL_MICRO: i128 = 150_000;

pub const SOURCE_REPOSITORY: &str = "Shtenco/synergy_agentic_ai_economy";
pub const SOURCE_COMMIT: &str = "113ef7df80d465958dc75e63b4afcd358dd39aa3";
