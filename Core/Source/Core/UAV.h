#pragma once

#include "Entity.h"

class gNB;
class UAV;
class UE;

#include "UE.h"
#include "gNB.h"

#include <vector>
#include <memory>
#include <map>

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

    // --- Authentication & Connection Placeholders ---

    // Receive connection request (SUCI) from UE
    void ReceiveConnectionRequest(int ueId, // Pass UE ID instead of object ref
                                  const std::vector<uint8_t>& c1_bytes,
                                  const std::vector<uint8_t>& c2_bytes,
                                  const std::vector<uint8_t>& mac_bytes);

    // --- Methods called by gNB to forward results to UE ---
    void SendAuthResponseToUE(int ueId, const std::vector<uint8_t>& res_star);
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

private:
    std::weak_ptr<gNB> m_ConnectedgNB; // The gNB this UAV is associated with
    std::map<int, std::weak_ptr<UE>> m_ConnectedUEs; // UEs connected via this UAV
    bool m_Operational = true; // Status flag

};
