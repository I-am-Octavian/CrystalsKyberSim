#include "gNB.h"
#include "UAV.h" // Include UAV to call its methods
#include "UE.h"   // Include UE for context (though maybe just ID is needed)
#include "KyberUtils.h"
#include <random>
#include <iostream>
#include <algorithm> // for std::equal

// Helper to generate random bytes (can be moved to a common utility)
std::vector<uint8_t> GenerateRandomBytesUtil(size_t numBytes) {
    std::vector<uint8_t> bytes(numBytes);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 255);
    for (size_t i = 0; i < numBytes; ++i) {
        bytes[i] = static_cast<uint8_t>(distrib(gen));
    }
    return bytes;
}

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

void gNB::ProcessAuthenticationRequest(const std::vector<uint8_t>& c1_bytes,
                                      const std::vector<uint8_t>& c2_bytes,
                                      const std::vector<uint8_t>& mac_bytes,
                                      UAV& originatingUAV,
                                      int ueId)
{
    std::cout << "gNB " << m_Id << ": Processing auth request (SUCI) from UE " << ueId << " via UAV " << originatingUAV.GetID() << std::endl;
    size_t c1_half_size = c1_bytes.size() / 2;
    std::vector<uint8_t> u_bytes(c1_bytes.begin(), c1_bytes.begin() + c1_half_size);
    std::vector<uint8_t> v_bytes(c1_bytes.begin() + c1_half_size, c1_bytes.end());
    Kyber::Polynomial u = Kyber::BytesToPoly(u_bytes, 2);
    Kyber::Polynomial v = Kyber::BytesToPoly(v_bytes, 1);
    auto skTu = Kyber::VecTransposeVecMul(m_Kyber_sk, u);
    auto v_minus_skTu = Kyber::PolySub(v, skTu);
    std::vector<uint8_t> rand_prime = Kyber::Compressq(v_minus_skTu, 1);
    std::vector<uint8_t> msk_prime = Kyber::KDF(rand_prime);
    std::vector<uint8_t> decrypted_c2 = Kyber::DMSK(c2_bytes);
    if (decrypted_c2.size() < 8) {
        std::cerr << "gNB " << m_Id << ": Error - Decrypted C2 too short!" << std::endl;
        HandleMacFailure(originatingUAV, ueId);
        return;
    }
    std::string supi_prime(decrypted_c2.begin(), decrypted_c2.end() - 8);
    std::vector<uint8_t> sqn_ue_prime_bytes(decrypted_c2.end() - 8, decrypted_c2.end());
    uint64_t sqn_ue_prime = Kyber::BytesToU64(sqn_ue_prime_bytes);
    std::cout << "gNB " << m_Id << ": Decrypted SUPI': " << supi_prime << ", SQN_UE': " << sqn_ue_prime << std::endl;
    if (m_UEKeys.find(supi_prime) == m_UEKeys.end()) {
        std::cerr << "gNB " << m_Id << ": Error - SUPI' " << supi_prime << " not found!" << std::endl;
        HandleMacFailure(originatingUAV, ueId);
        return;
    }
    const std::string& ue_key_K = m_UEKeys[supi_prime];
    std::vector<uint8_t> xmac_input = Kyber::ConcatBytes({sqn_ue_prime_bytes, rand_prime, m_AMF});
    std::vector<uint8_t> xmac = Kyber::f1K(ue_key_K, xmac_input);
    bool mac_ok = (xmac.size() == mac_bytes.size() && std::equal(xmac.begin(), xmac.end(), mac_bytes.begin()));
    if (!mac_ok) {
        std::cout << "gNB " << m_Id << ": MAC check failed for UE " << ueId << std::endl;
        HandleMacFailure(originatingUAV, ueId);
        return;
    }
    std::cout << "gNB " << m_Id << ": MAC check successful for UE " << ueId << std::endl;
    uint64_t last_sqn = m_UESequenceNumbers[supi_prime];
    bool sqn_ok = (sqn_ue_prime > last_sqn);
    if (!sqn_ok) {
        std::cout << "gNB " << m_Id << ": SQN check failed for UE " << ueId << " (SQN_UE'=" << sqn_ue_prime << ", LastSQN=" << last_sqn << ")" << std::endl;
        uint64_t sqn_hn = last_sqn;
        HandleSyncFailure(supi_prime, rand_prime, sqn_hn, originatingUAV, ueId);
        return;
    }
    std::cout << "gNB " << m_Id << ": SQN check successful for UE " << ueId << std::endl;
    m_UESequenceNumbers[supi_prime] = sqn_ue_prime;
    HandleAuthSuccess(supi_prime, rand_prime, sqn_ue_prime, originatingUAV, ueId);
}

void gNB::HandleAuthSuccess(const std::string& supi, const std::vector<uint8_t>& rand_prime, uint64_t sqn_ue_prime, UAV& uav, int ueId) {
    std::cout << "gNB " << m_Id << ": Authentication successful for SUPI " << supi << ". Proceeding to key generation." << std::endl;
    const std::string& K = m_UEKeys[supi];
    std::vector<uint8_t> res = Kyber::f2K(K, rand_prime);
    std::vector<uint8_t> ck = Kyber::f3K(K, rand_prime);
    std::vector<uint8_t> ik = Kyber::f4K(K, rand_prime);
    std::vector<uint8_t> ck_ik = Kyber::ConcatBytes({ck, ik});
    std::vector<uint8_t> net_name_bytes(m_ServingNetworkName.begin(), m_ServingNetworkName.end());
    std::vector<uint8_t> res_star_input = Kyber::ConcatBytes({net_name_bytes, rand_prime, res});
    for(size_t i=0; i<res_star_input.size() && i<ck_ik.size(); ++i) res_star_input[i] ^= ck_ik[i];
    std::vector<uint8_t> res_star = Kyber::KDF(res_star_input);
    std::vector<uint8_t> k_network = Kyber::KDF(Kyber::ConcatBytes({ck, ik}));
    std::cout << "gNB " << m_Id << ": Generated K_network (placeholder)." << std::endl;
    std::vector<uint8_t> nas_count = {0x00, 0x00, 0x00, 0x01};
    std::vector<uint8_t> access_type = {0x01};
    std::vector<uint8_t> k_ran_input = Kyber::ConcatBytes({nas_count, access_type, rand_prime});
    for(size_t i=0; i<k_ran_input.size() && i<k_network.size(); ++i) k_ran_input[i] ^= k_network[i];
    std::vector<uint8_t> k_ran = Kyber::KDF(k_ran_input);
    std::cout << "gNB " << m_Id << ": Generated K_RAN (placeholder)." << std::endl;
    uint64_t sqn_hn = sqn_ue_prime + 1;
    std::cout << "gNB " << m_Id << ": Sending Auth Response (RES*) to UAV " << uav.GetID() << " for UE " << ueId << std::endl;
    uav.SendAuthResponseToUE(ueId, res_star);
}

void gNB::HandleSyncFailure(const std::string& supi, const std::vector<uint8_t>& rand_prime, uint64_t sqn_hn, UAV& uav, int ueId) {
    std::cout << "gNB " << m_Id << ": SQN sync failure for SUPI " << supi << ". Sending AUTS." << std::endl;
    const std::string& K = m_UEKeys[supi];
    std::vector<uint8_t> sqn_hn_bytes = Kyber::U64ToBytes(sqn_hn);
    std::vector<uint8_t> macs_input = Kyber::ConcatBytes({sqn_hn_bytes, rand_prime, m_AMF});
    std::vector<uint8_t> macs = Kyber::f1_star_K(K, macs_input);
    std::vector<uint8_t> csqn = Kyber::EMSK(sqn_hn_bytes);
    std::vector<uint8_t> auts = Kyber::ConcatBytes({csqn, macs});
    std::cout << "gNB " << m_Id << ": Sending Sync Failure (AUTS) to UAV " << uav.GetID() << " for UE " << ueId << std::endl;
    uav.SendSyncFailureToUE(ueId, auts);
}

void gNB::HandleMacFailure(UAV& uav, int ueId) {
    std::cout << "gNB " << m_Id << ": MAC failure for UE " << ueId << ". Sending MAC Failure message." << std::endl;
    uav.SendMacFailureToUE(ueId);
}

void gNB::HandleUAVFailure(UAV& failedUAV)
{
    std::cout << "gNB " << m_Id << ": Handling failure of UAV " << failedUAV.GetID() << std::endl;
    if (!m_RegisteredUAVs.count(failedUAV.GetID())) return;

    auto affectedUEIds = failedUAV.GetConnectedUEIds();
    failedUAV.SetOperationalStatus(false);

    for (int ueId : affectedUEIds) {
        // Placeholder: Find the actual UE object (World class might help here)
        // Placeholder: Find the best *alternative* operational UAV for this UE
        // Placeholder: Command the UE to handover
        // Placeholder: Optionally inform the target UAV to expect the UE
    }
}

UAV* gNB::FindBestAlternativeUAV(const Position& uePosition)
{
    std::cout << "gNB " << m_Id << ": Searching for alternative UAV near (" << uePosition.first << ", " << uePosition.second << ")" << std::endl;
    return nullptr;
}
