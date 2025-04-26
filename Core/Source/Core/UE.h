#pragma once

#include "Entity.h"

class gNB;
class UAV;
class UE;

#include "UAV.h"
#include "gNB.h"
#include "KyberUtils.h"

#include <memory>
#include <iostream>
#include <vector>
#include <string>
#include <random>

//// Forward declarations for Kyber-related types, assuming they are implemented elsewhere
//namespace Kyber {
//    using Polynomial = std::vector<int>;
//
//    // Forward declarations of assumed Kyber functions
//    std::vector<uint8_t> Decompressq(const std::vector<uint8_t>& input, int parameter);
//    std::vector<uint8_t> KDF(const std::vector<uint8_t>& input);
//    std::vector<uint8_t> EMSK(const std::vector<uint8_t>& input);
//    std::vector<uint8_t> f1K(const std::vector<uint8_t>& input);
//}

class UE : public Entity {
public:
    UE(uint32_t xPos, uint32_t yPos, uint32_t xVel = 0, uint32_t yVel = 0, uint32_t id = 0,
        const std::string& theLongTermKey = "DEFAULT_KEY") // Use default key
        : Entity(xPos, yPos, xVel, yVel, id), m_LongTermKey(theLongTermKey)
    {
        m_SUPI = "SUPI_UE" + std::to_string(id); // Default SUPI based on ID
    }

    std::string GetType() const override { return "UE"; }
    const std::string& GetLongTermKey() const { return m_LongTermKey; }

    // --- Provisioning --- 
    void SetAuthenticationParameters(const std::string& supi,
                                     const std::string& key,
                                     const std::vector<uint8_t>& amf,
                                     const std::vector<uint8_t>& rho,
                                     const Kyber::Polynomial& pk);

    // --- Authentication & Connection ---

    // Initiates the first connection via a UAV to gNB by sending SUCI
    void InitiateConnection(UAV& targetUAV);

    // --- Handlers for gNB Responses (called by UAV) ---
    void HandleAuthResponse(const std::vector<uint8_t>& res_star);
    void HandleSyncFailure(const std::vector<uint8_t>& auts);
    void HandleMacFailure();
    void HandleGnbConnectionFailure(); // Called by UAV if gNB unreachable

    // UE initiates handover to a new UAV (no gNB involvement directly)
    void InitiateHandover(UAV& currentUAV, UAV& targetUAV);

    void ConfirmConnection(std::shared_ptr<UAV> uav, std::shared_ptr<gNB> gnb);

    void ConfirmHandover(std::shared_ptr<UAV> newUAV);

    // Called when the serving UAV instructs UE to handover (e.g., due to UAV failure)
    void ReceiveHandoverCommand(UAV& targetUAV);

    void Disconnect();

    inline int GetServingUAVId() const { return m_ServingUAVId; }
    inline const std::string& GetState() const { return m_UEState; }

private:
    // Generates a random 256-bit value
    std::vector<uint8_t> GenerateRandomBytes(size_t numBytes);

    Kyber::Polynomial SampleB3(size_t size);

    Kyber::Polynomial SampleB2(size_t size);

    std::pair<std::vector<uint8_t>, std::string> GenerateAuthParams();

    std::weak_ptr<UAV> m_ConnectedUAV; // Weak pointer to avoid cyclic dependencies
    std::weak_ptr<gNB> m_ConnectedgNB; // Connection via UAV
    int m_ServingUAVId = -1;
    int m_ServingGNBId = -1;
    std::string m_UEState = "Idle"; // e.g., Idle, Connecting, Connected, Handover, Failed

    // --- Provisioned Parameters ---
    std::string m_SUPI;                 // Subscriber Permanent Identifier
    std::string m_LongTermKey;          // Long-term secret key K
    std::vector<uint8_t> m_AMF;         // Authentication Management Field
    std::vector<uint8_t> m_Rho;         // Public parameter rho (for generating A)
    Kyber::Polynomial m_NetworkPK;      // Network public key pk
    Kyber::Matrix m_A;                  // Matrix A (generated from rho)

    // --- Authentication State ---
    std::vector<uint8_t> m_RAND;        // Current random value used in SUCI
    uint64_t m_SQN = 0;                 // Sequence number counter

    // --- Derived Keys (after successful auth) ---
    std::vector<uint8_t> m_CK;          // Ciphering Key
    std::vector<uint8_t> m_IK;          // Integrity Key
    std::vector<uint8_t> m_K_network;   // e.g., K_AMF
    std::vector<uint8_t> m_K_RAN;       // Key for RAN communication

};
