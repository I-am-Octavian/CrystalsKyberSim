#pragma once

#include "Entity.h"
#include "KyberUtils.h" // Include Kyber utilities

class gNB;
class UAV;
class UE;

#include "UAV.h"
#include "UE.h"

#include <map>
#include <memory>
#include <string>
#include <iostream>
#include <vector>
#include <set> // For authorized UAVs
#include <random>
#include <string>


// Helper to generate random bytes (can be moved to a common utility)
inline std::vector<uint8_t> GenerateRandomBytesUtil(size_t numBytes) {
    std::vector<uint8_t> bytes(numBytes);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 255);
    for (size_t i = 0; i < numBytes; ++i) {
        bytes[i] = static_cast<uint8_t>(distrib(gen));
    }
    return bytes;
}


// Base Station class (Ground RAN)
class gNB : public Entity, public std::enable_shared_from_this<gNB> { // Ensure enable_shared_from_this is on gNB itself
public:
    gNB(uint32_t xPos, uint32_t yPos, uint32_t xVel = 0, uint32_t yVel = 0, uint32_t id = 0)
        : Entity(xPos, yPos, xVel, yVel, id), m_AMF({0x00, 0x00}), m_ServingNetworkName("TestNet") // Initialize AMF and Network Name
    {
        SetupKyberParams(); // Generate keys on creation
    }

    std::string GetType() const override { return "gNB"; }
    const std::string& GetHomeNetworkPublicKey() const { return m_PublicKey; }
    const Kyber::Polynomial& GetKyberPublicKey() const { return m_Kyber_pk; }
    const std::vector<uint8_t>& GetKyberRho() const { return m_Kyber_rho; }
    const std::vector<uint8_t>& GetAMF() const { return m_AMF; }

    void RegisterUAV(std::shared_ptr<UAV> uav);

    // --- Authentication ---
    // Setup Kyber parameters for the gNB
    void SetupKyberParams();

    // Store UE's long-term key K (provisioning step)
    void ProvisionUEKey(const std::string& supi, const std::string& key);

    void ProvisionUAVKey(int uavId, const std::string& key);


    // Process authentication request (SUCI) forwarded by a UAV
    // SUCI = C1 || C2 || MAC || Other (Other is ignored for now)
    void ProcessAuthenticationRequest(const std::vector<uint8_t>& c1_bytes,
                                      const std::vector<uint8_t>& c2_bytes,
                                      const std::vector<uint8_t>& mac_bytes,
                                      UAV& originatingUAV, // Need UAV to send response back
                                      int ueId); // Need UE ID for context

    // Handle UAV failure: Find new UAVs for affected UEs
    void HandleUAVFailure(UAV& failedUAV);

    virtual UAV* FindBestAlternativeUAV(const Position& uePosition);

    // --- UAV Service Access Authentication (Phase A) ---
    // Called by gNB to initiate auth for a specific UAV
    void InitiateUAVServiceAccessAuth(int uavId);
    // Called by UAV to confirm successful authentication
    void ReceiveServiceAccessConfirmation(int uavId);

    // --- UAV-Assisted UE Access Authentication (Phase B) ---
    // Process auth request coming via an authenticated UAV
    void ProcessUAVAssistedAuthRequest(const std::vector<uint8_t>& suci_bytes,
                                       const std::string& tid_j, // UAV's Temp ID
                                       UAV& originatingUAV,
                                       int ueId);

    // --- UE Handover Authentication (Phase C) ---
    // Receive handover inform message from target UAV
    void ReceiveHandoverInform(const std::string& tid_star_j, const std::string& tid_i);

    // --- General ---
    void GenerateGroupKey(); // Generate GKUAV

private:
    // --- Authentication Success (Step 3)
    void HandleAuthSuccess(const std::string& supi, const std::vector<uint8_t>& rand_prime, uint64_t sqn_ue_prime, UAV& uav, int ueId);
    // Sync Failure (Step 3*)
    void HandleSyncFailure(const std::string& supi, const std::vector<uint8_t>& rand_prime, uint64_t sqn_hn, UAV& uav, int ueId);
    // MAC Failure (Step 3**)
    void HandleMacFailure(UAV& uav, int ueId);

    // --- Authentication State & Keys ---
    std::map<int, std::weak_ptr<UAV>> m_RegisteredUAVs; // UAVs associated with this gNB
    std::string m_PublicKey = "NULL"; // Legacy?
    std::string m_PrivateKey = "NULL"; // Legacy?

    std::map<int, std::string> m_UAVKeys;

    // Kyber and Protocol Parameters
    std::vector<uint8_t> m_Kyber_d;      // Initial seed
    std::vector<uint8_t> m_Kyber_rho;    // Public parameter rho
    std::vector<uint8_t> m_Kyber_sigma;  // Seed for s, e
    Kyber::Polynomial m_Kyber_sk;        // Secret key s (Polynomial)
    Kyber::Polynomial m_Kyber_pk;        // Public key pk = As + e (Polynomial)
    Kyber::Matrix m_Kyber_A;             // Matrix A generated from rho

    std::vector<uint8_t> m_AMF;          // Authentication Management Field
    std::string m_ServingNetworkName;    // Serving Network Name

    std::map<std::string, std::string> m_UEKeys; // Map SUPI -> Long-term key K
    std::map<std::string, uint64_t> m_UESequenceNumbers; // Map SUPI -> Last accepted SQN_UE (for replay protection)

    std::vector<uint8_t> m_GKUAV; // Group Key for UAVs
    std::map<int, std::vector<uint8_t>> m_UAV_KRANj; // Map UAV ID -> KRANj
    std::map<int, std::string> m_UAV_TIDj; // Map UAV ID -> TIDj
    std::set<int> m_AuthorizedUAVs; // Set of UAV IDs that completed Phase A

    // Store state during ongoing authentications
    struct OngoingUAVAuthInfo {
        std::vector<uint8_t> res_star_j; // Expected RES*j from UAV (or HRES*j?)
        std::vector<uint8_t> kran_j;     // Derived KRANj for this session
        // Add other necessary state from AKA...
    };
    std::map<int, OngoingUAVAuthInfo> m_OngoingUAVAuths; // Map UAV ID -> Auth Info

    struct OngoingUEAuthInfo {
         std::string tid_j;
         std::vector<uint8_t> kran_i; // Derived KRANi for UE session
         std::vector<uint8_t> res_star_i; // RES*i calculated for UE
         // Add other necessary state from AKA...
     };
    std::map<int, OngoingUEAuthInfo> m_OngoingUEAuths; // Map UE ID -> Auth Info

    // --- Private Helper Methods ---
    
    bool PerformStandardAKA_Step1_2(const std::vector<uint8_t>& suci_bytes,
                                     std::string& out_supi, uint64_t& out_sqn_ue,
                                     std::vector<uint8_t>& out_rand_prime,
                                     std::vector<uint8_t>& out_autn_or_auts, // AUTN on success, AUTS on sync fail
                                     bool& out_mac_ok, bool& out_sqn_ok);

    
    std::vector<uint8_t> DeriveKRAN(const std::string& supi_or_uav_id, const std::vector<uint8_t>& rand_prime);

    // Handle results of standard AKA for UAV
    void HandleUAV_AKA_Result(int uavId, bool mac_ok, bool sqn_ok, const std::vector<uint8_t>& autn_or_auts, const std::vector<uint8_t>& rand_prime);
    // Handle results of standard AKA for UE (via UAV)
    void HandleUE_AKA_Result(int ueId, UAV& uav, const std::string& tid_j, const std::string& supi, bool mac_ok, bool sqn_ok, const std::vector<uint8_t>& autn_or_auts, const std::vector<uint8_t>& rand_prime);
};
