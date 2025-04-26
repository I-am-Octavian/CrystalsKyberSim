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

// Base Station class
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

    // Process authentication request (SUCI) forwarded by a UAV
    // SUCI = C1 || C2 || MAC || Other (Other is ignored for now)
    void ProcessAuthenticationRequest(const std::vector<uint8_t>& c1_bytes,
                                      const std::vector<uint8_t>& c2_bytes,
                                      const std::vector<uint8_t>& mac_bytes,
                                      UAV& originatingUAV, // Need UAV to send response back
                                      int ueId); // Need UE ID for context

    // Handle UAV failure: Find new UAVs for affected UEs
    void HandleUAVFailure(UAV& failedUAV);

    // Helper function placeholder (implementation needed in World or similar)
    virtual UAV* FindBestAlternativeUAV(const Position& uePosition);

private:
    // Authentication Success (Step 3)
    void HandleAuthSuccess(const std::string& supi, const std::vector<uint8_t>& rand_prime, uint64_t sqn_ue_prime, UAV& uav, int ueId);
    // Sync Failure (Step 3*)
    void HandleSyncFailure(const std::string& supi, const std::vector<uint8_t>& rand_prime, uint64_t sqn_hn, UAV& uav, int ueId);
    // MAC Failure (Step 3**)
    void HandleMacFailure(UAV& uav, int ueId);

    std::map<int, std::weak_ptr<UAV>> m_RegisteredUAVs; // UAVs associated with this gNB
    std::string m_PublicKey = "NULL"; // Legacy?
    std::string m_PrivateKey = "NULL"; // Legacy?

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
};
