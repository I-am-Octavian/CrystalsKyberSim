#include "UAV.h"
#include "gNB.h" // Include gNB to call its methods
#include "UE.h"   // Include UE to call its methods (or World to find UE)
#include <iostream>

void UAV::ReceiveConnectionRequest(int ueId,
                                  const std::vector<uint8_t>& c1_bytes,
                                  const std::vector<uint8_t>& c2_bytes,
                                  const std::vector<uint8_t>& mac_bytes)
{
    std::cout << "UAV " << m_Id << ": Received connection request (SUCI) from UE " << ueId << std::endl;
    // Forward SUCI components to associated gNB
    if (auto gnb = m_ConnectedgNB.lock()) {
        gnb->ProcessAuthenticationRequest(c1_bytes, c2_bytes, mac_bytes, *this, ueId);
    } else {
        std::cerr << "UAV " << m_Id << ": No associated gNB to forward request!" << std::endl;
        // Optionally send a failure back to UE immediately
        // Find UE object (needs World context or similar)
        // if (auto ue_ptr = findUE(ueId)) { ue_ptr->HandleGnbConnectionFailure(); }
    }
}

void UAV::SendAuthResponseToUE(int ueId, const std::vector<uint8_t>& res_star) {
    std::cout << "UAV " << m_Id << ": Forwarding Auth Response (RES*) to UE " << ueId << std::endl;
    // Find the UE object (e.g., via World or stored map) and call its handler
    // Placeholder: Assume a function find_ue(id) exists
    /*
    if (auto ue_sp = find_ue(ueId).lock()) { // Assuming find_ue returns weak_ptr
         ue_sp->HandleAuthResponse(res_star);
         // If successful, update local state
         m_ConnectedUEs[ueId] = ue_sp; // Store weak_ptr to connected UE
    } else {
        std::cerr << "UAV " << m_Id << ": Could not find UE " << ueId << " to forward Auth Response." << std::endl;
    }
    */
     std::cout << "   (Placeholder: UAV finding UE " << ueId << " and calling HandleAuthResponse)" << std::endl;
     // Simulate adding UE locally on successful auth response forwarding
     // In real impl, UE confirms back before UAV adds it.
     // m_ConnectedUEs[ueId] = find_ue_weak_ptr(ueId); // Add weak ptr
}

void UAV::SendSyncFailureToUE(int ueId, const std::vector<uint8_t>& auts) {
    std::cout << "UAV " << m_Id << ": Forwarding Sync Failure (AUTS) to UE " << ueId << std::endl;
    // Find the UE object and call its handler
    /*
    if (auto ue_sp = find_ue(ueId).lock()) {
         ue_sp->HandleSyncFailure(auts);
    } else {
        std::cerr << "UAV " << m_Id << ": Could not find UE " << ueId << " to forward Sync Failure." << std::endl;
    }
    */
     std::cout << "   (Placeholder: UAV finding UE " << ueId << " and calling HandleSyncFailure)" << std::endl;
}

void UAV::SendMacFailureToUE(int ueId) {
    std::cout << "UAV " << m_Id << ": Forwarding MAC Failure to UE " << ueId << std::endl;
    // Find the UE object and call its handler
    /*
    if (auto ue_sp = find_ue(ueId).lock()) {
         ue_sp->HandleMacFailure();
    } else {
        std::cerr << "UAV " << m_Id << ": Could not find UE " << ueId << " to forward MAC Failure." << std::endl;
    }
    */
     std::cout << "   (Placeholder: UAV finding UE " << ueId << " and calling HandleMacFailure)" << std::endl;
}

void UAV::ReceiveHandoverRequest(UE& ue, UAV& sourceUAV)
{
    std::cout << "UAV " << m_Id << " (Target): Received handover request for UE " << ue.GetID() << " from UAV " << sourceUAV.GetID() << std::endl;
    // Placeholder: Perform local handover procedures (e.g., resource allocation)
    // Placeholder: Inform UE of completion
    // bool success = true; // Assume success for now
    // if (success) {
    //     m_ConnectedUEs[ue.id] = find_ue_shared_ptr(ue.id);
    //     ue.confirmHandover(get_self_shared_ptr());
    //     sourceUAV.releaseUE(ue.id);
    // }
}

void UAV::NotifyHandoverInitiated(UE& ue, UAV& targetUAV)
{
    std::cout << "UAV " << m_Id << " (Source): Notified that UE " << ue.GetID() << " is handing over to UAV " << targetUAV.GetID() << std::endl;
    // Placeholder: Prepare for releasing resources, but don't release yet
}

void UAV::ReleaseUE(int ueId)
{
    if (m_ConnectedUEs.count(ueId)) {
        m_ConnectedUEs.erase(ueId);
        std::cout << "UAV " << m_Id << ": Released connection for UE " << ueId << std::endl;
    }
}

void UAV::ReceiveHandoverConnection(UE& ue)
{
    std::cout << "UAV " << m_Id << ": Receiving handover connection for UE " << ue.GetID() << std::endl;
    // Placeholder: Similar to receiveAuthConfirmation, establish local connection
    // m_ConnectedUEs[ue.id] = find_ue_shared_ptr(ue.id);
    // ue.confirmHandover(get_self_shared_ptr());
}

std::vector<int> UAV::GetConnectedUEIds() const
{
    std::vector<int> ueIds;
    for (const auto& pair : m_ConnectedUEs) 
    {
        if (auto ue_sp = pair.second.lock()) 
        { // Check if UE still exists
            ueIds.push_back(pair.first);
        }
    }
    return ueIds;
}
