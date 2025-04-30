#include "gNB.h"
#include "UAV.h" // Include UAV to call its methods
#include "UE.h"   // Include UE for context (though maybe just ID is needed)
#include "KyberUtils.h"
#include <iostream>
#include <algorithm> // for std::equal
#include <stdexcept>

void gNB::RegisterUAV(std::shared_ptr<UAV> uav)
{
    m_RegisteredUAVs[uav->GetID()] = uav;
    uav->SetAssociatedGNB(std::static_pointer_cast<gNB>(shared_from_this())); // Requires enabling shared_from_this
    std::cout << "gNB " << m_Id << ": Registered UAV " << uav->GetID() << std::endl;
}

void gNB::SetupKyberParams() {
    std::cout << "gNB " << m_Id << ": Setting up Kyber parameters..." << std::endl;
    m_Kyber_d = GenerateRandomBytesUtil(32);
    auto seeds = Kyber::G(m_Kyber_d);
    m_Kyber_rho = seeds.first;
    m_Kyber_sigma = seeds.second;
    const size_t poly_vector_size = 2;
    m_Kyber_sk = Kyber::SampleB3(poly_vector_size, m_Kyber_sigma);
    auto e = Kyber::SampleB3(poly_vector_size, m_Kyber_sigma);
    m_Kyber_A = Kyber::GenerateA(m_Kyber_rho);
    auto As = Kyber::MatrixVecMul(m_Kyber_A, m_Kyber_sk);
    m_Kyber_pk = Kyber::PolyAdd(As, e);
    std::cout << "gNB " << m_Id << ": Kyber parameters generated." << std::endl;
}

void gNB::ProvisionUEKey(const std::string& supi, const std::string& key) {
    m_UEKeys[supi] = key;
    m_UESequenceNumbers[supi] = 0;
    std::cout << "gNB " << m_Id << ": Provisioned key for SUPI " << supi << std::endl;
}

void gNB::ProvisionUAVKey(int uavId, const std::string& key) {
    std::cout << "gNB " << m_Id << ": Provisioning key for UAV " << uavId << std::endl;
    m_UAVKeys[uavId] = key;
}

void gNB::GenerateGroupKey() {
    m_GKUAV = GenerateRandomBytesUtil(32); // Example 32-byte group key
    std::cout << "gNB " << m_Id << ": Generated new Group Key GKUAV (size=" << m_GKUAV.size() << ")" << std::endl;
}

void gNB::HandleSyncFailure(const std::string& supi, const std::vector<uint8_t>& rand_prime, uint64_t sqn_hn, UAV& uav, int ueId)
{
}

void gNB::HandleMacFailure(UAV& uav, int ueId)
{
}

void gNB::InitiateUAVServiceAccessAuth(int uavId) {
    std::cout << "gNB " << m_Id << ": Initiating Service Access Auth for UAV " << uavId << std::endl;
    auto uav_it = m_RegisteredUAVs.find(uavId);
    if (uav_it == m_RegisteredUAVs.end() || uav_it->second.expired()) {
        std::cerr << "gNB " << m_Id << ": Cannot initiate auth. UAV " << uavId << " not registered or expired." << std::endl;
        return;
    }
    auto uav = uav_it->second.lock();
     if (!uav) {
          std::cerr << "gNB " << m_Id << ": Cannot initiate auth. UAV " << uavId << " pointer invalid." << std::endl;
          return;
     }

    // Retrieve UAV's long-term key Kj
    if (m_UAVKeys.find(uavId) == m_UAVKeys.end()) {
        std::cerr << "gNB " << m_Id << ": Error - Long term key Kj not found for UAV " << uavId << "." << std::endl;
        return;
    }
    const std::string& uav_key_Kj = m_UAVKeys[uavId];
    std::cout << "gNB " << m_Id << ": Retrieved key Kj for UAV " << uavId << "." << std::endl;

    // --- Start AKA Steps ---
    // Step 1 & 2 (Simplified gNB side): Generate RAND', derive keys
    std::vector<uint8_t> rand_prime = GenerateRandomBytesUtil(32); // Generate fresh RAND'
    std::cout << "gNB " << m_Id << ": Generated RAND' for UAV " << uavId << " (size=" << rand_prime.size() << ")" << std::endl;

    // Derive CKj, IKj, RESj from Kj and RAND'
    std::vector<uint8_t> ckj = Kyber::f3K(uav_key_Kj, rand_prime);
    std::vector<uint8_t> ikj = Kyber::f4K(uav_key_Kj, rand_prime);
    std::vector<uint8_t> resj = Kyber::f2K(uav_key_Kj, rand_prime); // RESj
    std::cout << "gNB " << m_Id << ": Derived CKj, IKj, RESj for UAV " << uavId << "." << std::endl;

    // Derive KRANj = KDF(CKj || IKj, "KRAN") - "KRAN" is an example label
    std::vector<uint8_t> kran_key = ckj;
    kran_key.insert(kran_key.end(), ikj.begin(), ikj.end());
    std::vector<uint8_t> kran_j = Kyber::KDF(kran_key, Kyber::StringToBytes("KRAN"));
    m_UAV_KRANj[uavId] = kran_j; // Store KRANj
    std::cout << "gNB " << m_Id << ": Derived KRANj for UAV " << uavId << " (size=" << kran_j.size() << ")" << std::endl;

    // Step 3 (gNB side): Calculate RES*j = KDF(CKj || IKj, SNN || RAND' || RESj)
    std::vector<uint8_t> res_star_input = Kyber::StringToBytes(m_ServingNetworkName);
    res_star_input.insert(res_star_input.end(), rand_prime.begin(), rand_prime.end());
    res_star_input.insert(res_star_input.end(), resj.begin(), resj.end());
    std::vector<uint8_t> res_star_j = Kyber::KDF(kran_key, res_star_input); // Using CK||IK as key
    std::cout << "gNB " << m_Id << ": Calculated RES*j for UAV " << uavId << " (size=" << res_star_j.size() << ")" << std::endl;

    // --- End AKA Steps ---

    // Step 4: Generate TIDj, compute Cj, HRES*j
    if (m_GKUAV.empty()) {
        GenerateGroupKey();
    }

    std::string tid_j = Kyber::GenerateTID("TID_UAV_" + std::to_string(uavId));
    m_UAV_TIDj[uavId] = tid_j; // Store TIDj

    // Compute Cj = E_KRANj(TIDj || GKUAV)
    std::vector<uint8_t> tidj_bytes = Kyber::StringToBytes(tid_j);
    std::vector<uint8_t> cj_plaintext = tidj_bytes;
    cj_plaintext.insert(cj_plaintext.end(), m_GKUAV.begin(), m_GKUAV.end());
    std::vector<uint8_t> cj = Kyber::EncryptSymmetric(kran_j, cj_plaintext);
    std::cout << "gNB " << m_Id << ": Computed Cj for UAV " << uavId << " (size=" << cj.size() << ")" << std::endl;

    // Compute HRES*j = KDF(KRANj, Cj || RES*j)
    std::vector<uint8_t> hres_input = cj;
    hres_input.insert(hres_input.end(), res_star_j.begin(), res_star_j.end());
    std::vector<uint8_t> hres_star_j = Kyber::KDF(kran_j, hres_input);
    std::cout << "gNB " << m_Id << ": Computed HRES*j for UAV " << uavId << " (size=" << hres_star_j.size() << ")" << std::endl;

    // Send (HRES*j, Cj, RAND') to UAV
    std::cout << "gNB " << m_Id << ": Sending (HRES*j, Cj, RAND') to UAV " << uavId << std::endl;
    // Pass RAND' so UAV can perform its calculations
    uav->ReceiveServiceAccessAuthParams(hres_star_j, cj, rand_prime);
}

void gNB::ReceiveServiceAccessConfirmation(int uavId) {
    std::cout << "gNB " << m_Id << ": Received Service Access Confirmation from UAV " << uavId << std::endl;
    if (m_UAV_KRANj.count(uavId) && m_UAV_TIDj.count(uavId)) {
        m_AuthorizedUAVs.insert(uavId);
        std::cout << "gNB " << m_Id << ": UAV " << uavId << " successfully authenticated and authorized." << std::endl;
        auto uav_it = m_RegisteredUAVs.find(uavId);
        if (uav_it != m_RegisteredUAVs.end()) {
            if(auto uav_sp = uav_it->second.lock()) {
                uav_sp->BroadcastNotification();
            }
        }
    } else {
        std::cerr << "gNB " << m_Id << ": Received unexpected confirmation from UAV " << uavId << " (missing state)." << std::endl;
    }
}

void gNB::ProcessUAVAssistedAuthRequest(const std::vector<uint8_t>& suci_bytes,
                                        const std::string& tid_j,
                                        UAV& originatingUAV,
                                        int ueId) {
    std::cout << "gNB " << m_Id << ": Processing UAV-Assisted Auth Request for UE " << ueId << " via UAV " << originatingUAV.GetID() << " (TIDj=" << tid_j << ")" << std::endl;

    if (m_AuthorizedUAVs.find(originatingUAV.GetID()) == m_AuthorizedUAVs.end() || m_UAV_TIDj[originatingUAV.GetID()] != tid_j) {
        std::cerr << "gNB " << m_Id << ": Auth request rejected. UAV " << originatingUAV.GetID() << " not authorized or TIDj mismatch." << std::endl;
        return;
    }
    std::cout << "gNB " << m_Id << ": Originating UAV " << originatingUAV.GetID() << " is authorized." << std::endl;

    std::string supi_prime;
    uint64_t sqn_ue_prime;
    std::vector<uint8_t> rand_prime;
    std::vector<uint8_t> autn_or_auts;
    bool mac_ok, sqn_ok;

    bool aka_step1_2_ok = PerformStandardAKA_Step1_2(suci_bytes, supi_prime, sqn_ue_prime, rand_prime, autn_or_auts, mac_ok, sqn_ok);

    bool ue_authorized = true; // Assume authorized if AKA passes basic checks
    if (!aka_step1_2_ok || !ue_authorized) {
        std::cerr << "gNB " << m_Id << ": UE " << ueId << " authentication failed or not authorized." << std::endl;
        if (!mac_ok) {
            std::cout << "gNB " << m_Id << ": Sending MAC Failure to UAV " << originatingUAV.GetID() << " for UE " << ueId << std::endl;
            originatingUAV.SendMacFailureToUE(ueId);
        } else if (!sqn_ok) {
            std::cout << "gNB " << m_Id << ": Sending Sync Failure (AUTS) to UAV " << originatingUAV.GetID() << " for UE " << ueId << std::endl;
            originatingUAV.SendSyncFailureToUE(ueId, autn_or_auts);
        }
        return;
    }
    std::cout << "gNB " << m_Id << ": UE " << ueId << " (SUPI=" << supi_prime << ") passed initial AKA checks and is authorized." << std::endl;
    m_UESequenceNumbers[supi_prime] = sqn_ue_prime;

    std::string tid_i = Kyber::GenerateTID("TID_UE_" + std::to_string(ueId));

    std::vector<uint8_t> kran_i = DeriveKRAN(supi_prime, rand_prime);
    std::cout << "gNB " << m_Id << ": Derived KRANi for UE " << ueId << " (size=" << kran_i.size() << ")" << std::endl;

    std::vector<uint8_t> tidi_bytes = Kyber::StringToBytes(tid_i);
    std::vector<uint8_t> tidj_bytes = Kyber::StringToBytes(tid_j);
    std::vector<uint8_t> kuavi_input = tidi_bytes;
    kuavi_input.insert(kuavi_input.end(), tidj_bytes.begin(), tidj_bytes.end());
    std::vector<uint8_t> kuav_i = Kyber::KDF(kran_i, kuavi_input);
    std::cout << "gNB " << m_Id << ": Computed KUAVi for UE " << ueId << " (size=" << kuav_i.size() << ")" << std::endl;

    Kyber::Timestamp tst = Kyber::GenerateTST(3600);
    std::vector<uint8_t> tst_bytes = Kyber::TimestampToBytes(tst);
    std::vector<uint8_t> tgki_input = tidi_bytes;
    tgki_input.insert(tgki_input.end(), tst_bytes.begin(), tst_bytes.end());
    std::vector<uint8_t> tgk_i = Kyber::KDF(m_GKUAV, tgki_input);
    std::cout << "gNB " << m_Id << ": Computed TGKi for UE " << ueId << " (size=" << tgk_i.size() << ")" << std::endl;

    std::vector<uint8_t> token_i = tgk_i;
    token_i.insert(token_i.end(), tst_bytes.begin(), tst_bytes.end());
    std::cout << "gNB " << m_Id << ": Computed Tokeni for UE " << ueId << " (size=" << token_i.size() << ")" << std::endl;

    std::vector<uint8_t> ci_plaintext = tidi_bytes;
    ci_plaintext.insert(ci_plaintext.end(), token_i.begin(), token_i.end());
    std::vector<uint8_t> ci = Kyber::EncryptSymmetric(kran_i, ci_plaintext);
    std::cout << "gNB " << m_Id << ": Computed Ci for UE " << ueId << " (size=" << ci.size() << ")" << std::endl;

    const std::string& K = m_UEKeys[supi_prime];
    std::vector<uint8_t> res_i = Kyber::f2K(K, rand_prime);
    std::vector<uint8_t> ck = Kyber::f3K(K, rand_prime);
    std::vector<uint8_t> ik = Kyber::f4K(K, rand_prime);
    std::vector<uint8_t> ck_ik = Kyber::ConcatBytes({ck, ik});
    std::vector<uint8_t> net_name_bytes(m_ServingNetworkName.begin(), m_ServingNetworkName.end());
    std::vector<uint8_t> res_star_input = Kyber::ConcatBytes({net_name_bytes, rand_prime, res_i});
    for(size_t i=0; i<res_star_input.size() && i<ck_ik.size(); ++i) res_star_input[i] ^= ck_ik[i];
    std::vector<uint8_t> res_star_i = Kyber::KDF(res_star_input);

    std::vector<uint8_t> hres_input = ci;
    hres_input.insert(hres_input.end(), res_star_i.begin(), res_star_i.end());
    std::vector<uint8_t> hres_star_i = Kyber::KDF(kran_i, hres_input);
    std::cout << "gNB " << m_Id << ": Computed HRES*i for UE " << ueId << " (size=" << hres_star_i.size() << ")" << std::endl;

    std::cout << "gNB " << m_Id << ": Sending UE Auth Params (HRES*i, Ci, TIDi, KUAVi) to UAV " << originatingUAV.GetID() << " for UE " << ueId << std::endl;
    originatingUAV.ReceiveUEAuthParams(ueId, hres_star_i, ci, tid_i, kuav_i);
}

void gNB::ReceiveHandoverInform(const std::string& tid_star_j, const std::string& tid_i) {
    std::cout << "gNB " << m_Id << ": Received Handover Inform message." << std::endl;
    std::cout << "   Target UAV TID*: " << tid_star_j << std::endl;
    std::cout << "   UE TID: " << tid_i << std::endl;
    std::cout << "gNB " << m_Id << ": Noted successful handover." << std::endl;
}

bool gNB::PerformStandardAKA_Step1_2(const std::vector<uint8_t>& suci_bytes,
                                     std::string& out_supi, uint64_t& out_sqn_ue,
                                     std::vector<uint8_t>& out_rand_prime,
                                     std::vector<uint8_t>& out_autn_or_auts,
                                     bool& out_mac_ok, bool& out_sqn_ok)
{
    std::cout << "gNB " << m_Id << ": Performing Standard AKA Steps 1 & 2..." << std::endl;
    out_mac_ok = false;
    out_sqn_ok = false;

    if (suci_bytes.size() < 50) {
        std::cerr << "gNB " << m_Id << ": Error - SUCI too short!" << std::endl;
        return false;
    }
    size_t mac_size = 42;
    size_t c2_size = 18;
    size_t c1_size = suci_bytes.size() - c2_size - mac_size;
    std::vector<uint8_t> c1_bytes(suci_bytes.begin(), suci_bytes.begin() + c1_size);
    std::vector<uint8_t> c2_bytes(suci_bytes.begin() + c1_size, suci_bytes.begin() + c1_size + c2_size);
    std::vector<uint8_t> mac_bytes(suci_bytes.begin() + c1_size + c2_size, suci_bytes.end());

    std::cout << "gNB " << m_Id << ": Parsed SUCI (C1 size=" << c1_bytes.size() << ", C2 size=" << c2_bytes.size() << ", MAC size=" << mac_bytes.size() << ")" << std::endl;

    std::cout << "gNB " << m_Id << ": Decrypting C1..." << std::endl;
    out_rand_prime = Kyber::Compressq(Kyber::Polynomial(), 1);
    std::cout << "gNB " << m_Id << ": Got RAND' (size=" << out_rand_prime.size() << ")" << std::endl;

    std::vector<uint8_t> msk_prime = Kyber::KDF(out_rand_prime);
    std::vector<uint8_t> decrypted_c2 = Kyber::DMSK(c2_bytes);
    if (decrypted_c2.size() < 9) {
        std::cerr << "gNB " << m_Id << ": Error - Decrypted C2 too short!" << std::endl;
        return false;
    }
    out_supi = Kyber::BytesToString(std::vector<uint8_t>(decrypted_c2.begin(), decrypted_c2.end() - 8));
    std::vector<uint8_t> sqn_ue_prime_bytes(decrypted_c2.end() - 8, decrypted_c2.end());
    out_sqn_ue = Kyber::BytesToU64(sqn_ue_prime_bytes);
    std::cout << "gNB " << m_Id << ": Decrypted C2. Got SUPI'=" << out_supi << ", SQN_UE'=" << out_sqn_ue << std::endl;

    if (m_UEKeys.find(out_supi) == m_UEKeys.end()) {
        std::cerr << "gNB " << m_Id << ": Error - SUPI' " << out_supi << " not found!" << std::endl;
        return false;
    }
    const std::string& ue_key_K = m_UEKeys[out_supi];
    std::cout << "gNB " << m_Id << ": Found key K for SUPI' " << out_supi << "." << std::endl;

    std::vector<uint8_t> xmac_input = Kyber::ConcatBytes({sqn_ue_prime_bytes, out_rand_prime, m_AMF});
    std::vector<uint8_t> xmac = Kyber::f1K(ue_key_K, xmac_input);
    std::cout << "gNB " << m_Id << ": Calculated XMAC." << std::endl;

    out_mac_ok = (xmac.size() == mac_bytes.size() && std::equal(xmac.begin(), xmac.end(), mac_bytes.begin()));
    if (!out_mac_ok) {
        std::cout << "gNB " << m_Id << ": MAC check failed." << std::endl;
        return false;
    }
    std::cout << "gNB " << m_Id << ": MAC check successful." << std::endl;

    uint64_t last_sqn = m_UESequenceNumbers[out_supi];
    out_sqn_ok = (out_sqn_ue > last_sqn);
    if (!out_sqn_ok) {
        std::cout << "gNB " << m_Id << ": SQN check failed (SQN_UE'=" << out_sqn_ue << ", LastSQN=" << last_sqn << ")" << std::endl;
        uint64_t sqn_hn = last_sqn;
        std::vector<uint8_t> sqn_hn_bytes = Kyber::U64ToBytes(sqn_hn);
        std::vector<uint8_t> macs_input = Kyber::ConcatBytes({sqn_hn_bytes, out_rand_prime, m_AMF});
        std::vector<uint8_t> macs = Kyber::f1_star_K(ue_key_K, macs_input);
        std::vector<uint8_t> csqn = Kyber::EMSK(sqn_hn_bytes);
        out_autn_or_auts = Kyber::ConcatBytes({csqn, macs});
        std::cout << "gNB " << m_Id << ": Generated AUTS for Sync Failure." << std::endl;
        return false;
    }
    std::cout << "gNB " << m_Id << ": SQN check successful." << std::endl;

    out_autn_or_auts = {};
    std::cout << "gNB " << m_Id << ": AKA Steps 1 & 2 successful." << std::endl;
    return true;
}

std::vector<uint8_t> gNB::DeriveKRAN(const std::string& id, const std::vector<uint8_t>& rand_prime) {
    std::cout << "gNB " << m_Id << ": Deriving KRAN for " << id << std::endl;
    return Kyber::KDF(Kyber::StringToBytes(m_UEKeys[id]), rand_prime);

    std::string key_material = "KRAN_for_" + id;
    std::vector<uint8_t> input = Kyber::StringToBytes(key_material);
    input.insert(input.end(), rand_prime.begin(), rand_prime.end());
    return Kyber::KDF(input);
}

void gNB::HandleUAVFailure(UAV& failedUAV)
{
    std::cout << "gNB " << m_Id << ": Handling failure of UAV " << failedUAV.GetID() << std::endl;
    if (!m_RegisteredUAVs.count(failedUAV.GetID())) return;

    auto affectedUEIds = failedUAV.GetConnectedUEIds();
    failedUAV.SetOperationalStatus(false);

    for (int ueId : affectedUEIds) {
        
        
        
        
    }
}

UAV* gNB::FindBestAlternativeUAV(const Position& uePosition)
{
    std::cout << "gNB " << m_Id << ": Searching for alternative UAV near (" << uePosition.first << ", " << uePosition.second << ")" << std::endl;
    return nullptr;
}
