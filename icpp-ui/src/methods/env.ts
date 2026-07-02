// =====================
// Environment variables
// Privacy ICP (ICPP)
// v 2.0.03 Dec 2025
// @troesma
// =====================

export interface ICPPEnv {
  HOST: string;
  NETWORK: "ic";
  II_URL: string;

  DERIVATION_ORIGIN: string;

  CANISTER_IDS: {
    router: string;
    crypto: string;
    noticeboard: string;
    registry: string;

    ledger: string; 
    cmc: string;
    internet_identity: string;
    icpp_ui: string;
  };
}

export const ENV: ICPPEnv = {
  HOST: "https://ic0.app",
  NETWORK: "ic",
  II_URL: "https://id.ai",

  DERIVATION_ORIGIN: "https://tuaah-oaaaa-aaaai-atxdq-cai.icp0.io",

  CANISTER_IDS: {
    router: "tbhrk-piaaa-aaaai-atxaa-cai",
    crypto: "yrto4-pqaaa-aaaai-atw6q-cai",
    noticeboard: "tie2w-zaaaa-aaaai-atxbq-cai",
    registry: "ttbgt-dyaaa-aaaai-atxda-cai",
    ledger: "ryjl3-tyaaa-aaaaa-aaaba-cai",
    cmc: "rkp4c-7iaaa-aaaaa-aaaca-cai",
    internet_identity: "rdmx6-jaaaa-aaaaa-aaadq-cai",
    icpp_ui: "tuaah-oaaaa-aaaai-atxdq-cai",
  },
};

