#pragma once

#include "Entity.h"
#include "KyberUtils.h" // Include Kyber utilities

class gNB;
class UAV;
class UE;

#include "UE.h"
#include "gNB.h"

#include <vector>
#include <memory>
#include <map>
#include <string> // For TID
#include <optional> // For optional values
#include <functional>
#include <string>

// Unmanned Aerial Vehicle class (acts as a relay)
class UAV : public Entity {
public:
    UAV(uint32_t xPos, uint32_t yPos, uint32_t xVel = 0, uint32_t yVel = 0, uint32_t id = 0) 
        : Entity(xPos, yPos, xVel, yVel, id) {}

    std::string GetType() const override { return "UAV"; }

    inline void SetAssociatedGNB(std::shared_ptr<gNB> gnb) { m_ConnectedgNB = gnb; }
    inline std::weak_ptr<gNB> GetAssociatedGNB() const { return m_ConnectedgNB; }

    inline bool IsOperational() const { return m_Operational; }

    inline void SetOperationalStatus(bool status) { m_Operational = status; 
        std::cout << "UAV " << m_Id << ": Operational status set to " << (status ? "true" : "false") << std::endl;
    }

    void SetLongTermKey(const std::string& key);

    // --- UAV Service Access Authentication (Phase A) ---
    // Called by gNB after successful AKA steps
    // void ReceiveServiceAccessAuthParams(const std::vector<uint8_t>& hres_star_j, const std::vector<uint8_t>& cj);
    void ReceiveServiceAccessAuthParams(const std::vector<uint8_t>& hres_star_j,
        const std::vector<uint8_t>& cj,
        const std::vector<uint8_t>& rand_prime); // Add rand_prime

    // Called by UAV after verifying HRES*j
    void ConfirmServiceAccessAuth(); // Sends confirmation to gNB

    // --- UAV-Assisted UE Access Authentication (Phase B) ---
    // Modified ReceiveConnectionRequest to include TIDj
    void ReceiveConnectionRequest(int ueId,
                                  const std::vector<uint8_t>& suci_bytes); // SUCI includes C1, C2, MAC

    // Called by gNB to forward UE auth params
    void ReceiveUEAuthParams(int ueId,
                             const std::vector<uint8_t>& hres_star_i,
                             const std::vector<uint8_t>& ci,
                             const std::string& tid_i,
                             const std::vector<uint8_t>& kuav_i);

    // --- UE Handover Authentication (Phase C) ---
    // Receive handover request from UE
    void ReceiveHandoverAuthRequest(int ueId,
                                    const std::string& tid_i,
                                    const std::vector<uint8_t>& mac_i,
                                    const std::vector<uint8_t>& r1,
                                    const Kyber::Timestamp& tst);

    // Receive handover confirmation from UE
    void ReceiveHandoverAuthConfirmation(int ueId, const std::vector<uint8_t>& xres_i);

    // --- General ---
    inline const std::string& GetTID() const { return m_TIDj; }
    inline bool IsAuthenticatedWithGNB() const { return m_IsAuthenticatedWithGNB; }
    void BroadcastNotification(); // Broadcast TIDj

    // Placeholder for finding UE (replace with World lookup)
    virtual std::shared_ptr<UE> FindUEById(int ueId) 
    {
        if (findUEHandler)
            return findUEHandler(ueId);
        else
            return nullptr; 
    }
    // Placeholder for getting self shared_ptr (replace with World mechanism or pass shared_ptr)
    virtual std::shared_ptr<UAV> GetSelfPtr() 
    {
        if (getSelfPtrHandler)
            return getSelfPtrHandler();
        else
            return nullptr;
    }

    // --- Methods called by gNB to forward results to UE ---
    //void SendAuthResponseToUE(int ueId, const std::vector<uint8_t>& res_star);
    void SendSyncFailureToUE(int ueId, const std::vector<uint8_t>& auts);
    void SendMacFailureToUE(int ueId);

    // UE-initiated Handover: Target UAV receives request
    void ReceiveHandoverRequest(UE& ue, UAV& sourceUAV);

    // UE-initiated Handover: Source UAV is notified
    void NotifyHandoverInitiated(UE& ue, UAV& targetUAV);

    // Called by source UAV when handover is complete or by gNB on failure
    void ReleaseUE(int ueId);

    // Receive connection request from UE during gNB-coordinated handover (after failure)
    void ReceiveHandoverConnection(UE& ue);

    // Get list of connected UE IDs (for gNB during failure handover)
    std::vector<int> GetConnectedUEIds() const;

    std::function<std::shared_ptr<UE>(int)> findUEHandler;
    std::function<std::shared_ptr<UAV>()> getSelfPtrHandler;

private:
    std::weak_ptr<gNB> m_ConnectedgNB; // The gNB this UAV is associated with
    std::map<int, std::weak_ptr<UE>> m_ConnectedUEs; // UEs connected via this UAV
    bool m_Operational = true; // Status flag

    std::string m_LongTermKey_Kj; // UAV's long-term key
    std::vector<uint8_t> m_Current_RAND_j; // Store RAND' for current session
    std::vector<uint8_t> m_Derived_CKj; // Derived CKj
    std::vector<uint8_t> m_Derived_IKj; // Derived IKj
    std::vector<uint8_t> m_Derived_RESj; // Derived RESj


    bool m_IsAuthenticatedWithGNB = false;
    std::string m_TIDj = ""; // Temporary Identity assigned by gNB
    std::vector<uint8_t> m_KRANj; // Key derived during UAV auth with gNB
    std::vector<uint8_t> m_GKUAV; // Group Key for UAVs

    // State for ongoing authentications
    std::map<int, std::vector<uint8_t>> m_PendingUEAuth_C1; // Store C1 from SUCI temporarily if needed
    std::map<int, std::vector<uint8_t>> m_PendingUEAuth_RES_star_i; // Store RES*i for UE confirmation

    // State for UE connections established via this UAV
    struct UEConnectionInfo {
        std::string tid_i;
        std::vector<uint8_t> kuav_i; // Key between UE and this UAV
        std::vector<uint8_t> r1; // Store R1 during handover
        std::vector<uint8_t> expected_res_i; // Store RESi during handover
    };
    std::map<int, UEConnectionInfo> m_ConnectedUEInfo; // Map UE ID -> Info

    // Helper to get associated gNB shared_ptr
    std::shared_ptr<gNB> GetAssociatedGNBShared() const;

};
