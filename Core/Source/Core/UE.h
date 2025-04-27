#pragma once

#include "Entity.h"
#include "KyberUtils.h" // Include Kyber utilities

class gNB;
class UAV;
class UE;

#include "UAV.h"
#include "gNB.h"

#include <memory>
#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <optional> // For optional values

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

    // --- UAV-Assisted UE Access Authentication (Phase B) ---
    // Modified InitiateConnection to send SUCI
    void InitiateConnection(UAV& targetUAV); // Sends SUCI

    // Handle response from UAV (HRES*i, Ci)
    void HandleUAVAssistedAuthResponse(const std::vector<uint8_t>& hres_star_i,
                                       const std::vector<uint8_t>& ci,
                                       const std::string& tid_j); // UAV's TID needed for KUAVi calc

    // --- UE Handover Authentication (Phase C) ---
    // Initiate handover authentication with a target UAV
    void InitiateHandoverAuthentication(UAV& targetUAV);

    // Handle challenge (HRESi, R2) from target UAV
    void HandleHandoverAuthChallenge(const std::vector<uint8_t>& hres_i,
                                     const std::vector<uint8_t>& r2);

    // --- Connection Management ---
    void ConfirmConnection(std::shared_ptr<UAV> uav, std::shared_ptr<gNB> gnb);

    void ConfirmHandover(std::shared_ptr<UAV> newUAV);

    void Disconnect();

    inline int GetServingUAVId() const { return m_ServingUAVId; }
    inline const std::string& GetState() const { return m_UEState; }

    // --- Handlers for Standard AKA Failures (called by UAV) ---
    void HandleSyncFailure(const std::vector<uint8_t>& auts);
    void HandleMacFailure();
    void HandleGnbConnectionFailure(); // Called by UAV if gNB unreachable

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

    // --- New State for UAV Protocol ---
    std::string m_TIDi = ""; // Temporary Identity assigned by gNB
    std::vector<uint8_t> m_KUAVi; // Key shared with current serving UAV
    std::vector<uint8_t> m_Tokeni; // Token received from gNB (TGKi || TST)
    std::vector<uint8_t> m_TGKi; // Temporary Group Key derived from Token
    Kyber::Timestamp m_TST; // Expiration time from Token

    std::vector<uint8_t> m_KRANi; // Key derived during AKA with gNB

    // State during handover
    std::vector<uint8_t> m_Handover_R1; // Store R1 during handover
    std::string m_Handover_TargetTIDj = ""; // Store Target UAV TIDj during handover
    std::weak_ptr<UAV> m_Handover_TargetUAV; // Store target UAV during handover

    // Helper to get connected UAV shared_ptr
    std::shared_ptr<UAV> GetConnectedUAVShared() const;
};
