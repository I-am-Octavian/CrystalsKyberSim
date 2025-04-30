#include "UAV.h"
#include "gNB.h" // Include gNB to call its methods
#include "UE.h"  // Include UE to call its methods
#include "KyberUtils.h"
#include <iostream>
#include <stdexcept> // For exceptions
#include <string>    // Ensure string is included
#include <vector>    // Ensure vector is included

// Helper to get associated gNB shared_ptr
std::shared_ptr<gNB> UAV::GetAssociatedGNBShared() const
{
    if (auto gnb_sp = m_ConnectedgNB.lock())
    {
        return gnb_sp;
    }
    std::cerr << "UAV " << m_Id << ": Error - No associated gNB found!" << std::endl;
    return nullptr;
}

// --- UAV Service Access Authentication (Phase A) ---

// void UAV::ReceiveServiceAccessAuthParams(const std::vector<uint8_t>& hres_star_j, const std::vector<uint8_t>& cj) {
//     std::cout << "UAV " << m_Id << ": Received Service Access Auth Params (HRES*j, Cj) from gNB." << std::endl;


//     // For simulation, assume we have derived KRANj and XRES*j somehow.



//     std::vector<uint8_t> cj_and_xres_star_j = cj;

//     std::vector<uint8_t> hxres_star_j = Kyber::KDF(m_KRANj, cj_and_xres_star_j);

//     std::cout << "UAV " << m_Id << ": Calculated HXRES*j." << std::endl;

//     if (hxres_star_j == hres_star_j) {
//         std::cout << "UAV " << m_Id << ": HRES*j matches HXRES*j. Authenticating gNB." << std::endl;
//         std::vector<uint8_t> decrypted_cj = Kyber::DecryptSymmetric(m_KRANj, cj);


//         // Assuming format: [TIDj_bytes][GKUAV_bytes]
//         if (decrypted_cj.size() > 10) { // Arbitrary minimum size
//             size_t tid_len = 10; // Example fixed length
//             m_TIDj = Kyber::BytesToString(std::vector<uint8_t>(decrypted_cj.begin(), decrypted_cj.begin() + tid_len));
//             m_GKUAV = std::vector<uint8_t>(decrypted_cj.begin() + tid_len, decrypted_cj.end());
//             m_IsAuthenticatedWithGNB = true;
//             std::cout << "UAV " << m_Id << ": Decrypted Cj. Got TIDj=" << m_TIDj << ", GKUAV (size=" << m_GKUAV.size() << "). Storing keys." << std::endl;



//             ConfirmServiceAccessAuth(); // Send confirmation back to gNB
//         } else {
//             std::cerr << "UAV " << m_Id << ": Error - Decrypted Cj is too short." << std::endl;
//             m_IsAuthenticatedWithGNB = false;
//         }
//     } else {
//         std::cerr << "UAV " << m_Id << ": Error - HRES*j mismatch! Authentication failed." << std::endl;
//         m_IsAuthenticatedWithGNB = false;
//     }
// }

void UAV::ReceiveServiceAccessAuthParams(const std::vector<uint8_t> &hres_star_j,
                                         const std::vector<uint8_t> &cj,
                                         const std::vector<uint8_t> &rand_prime)
{ // Add rand_prime
    std::cout << "UAV " << m_Id << ": Received Service Access Auth Params (HRES*j, Cj, RAND') from gNB." << std::endl;
    m_Current_RAND_j = rand_prime; // Store RAND'

    if (m_LongTermKey_Kj.empty())
    {
        std::cerr << "UAV " << m_Id << ": Error - Long term key Kj not set. Cannot proceed." << std::endl;
        return;
    }

    // --- Start AKA Steps (UAV side) ---
    // Step 1 & 2: Derive keys using own Kj and received RAND'
    m_Derived_CKj = Kyber::f3K(m_LongTermKey_Kj, m_Current_RAND_j);
    m_Derived_IKj = Kyber::f4K(m_LongTermKey_Kj, m_Current_RAND_j);
    m_Derived_RESj = Kyber::f2K(m_LongTermKey_Kj, m_Current_RAND_j); // RESj
    std::cout << "UAV " << m_Id << ": Derived CKj, IKj, RESj." << std::endl;

    // Derive KRANj = KDF(CKj || IKj, "KRAN")
    std::vector<uint8_t> kran_key = m_Derived_CKj;
    kran_key.insert(kran_key.end(), m_Derived_IKj.begin(), m_Derived_IKj.end());
    std::vector<uint8_t> derived_kran_j = Kyber::KDF(kran_key, Kyber::StringToBytes("KRAN"));
    std::cout << "UAV " << m_Id << ": Derived KRANj (size=" << derived_kran_j.size() << ")" << std::endl;

    // Step 3: Calculate XRES*j = KDF(CKj || IKj, SNN || RAND' || RESj)
    // Assume UAV knows the SNN (Serving Network Name) - needs configuration/provisioning
    std::string serving_network_name = "TestNet"; 
    std::vector<uint8_t> xres_star_input = Kyber::StringToBytes(serving_network_name);
    xres_star_input.insert(xres_star_input.end(), m_Current_RAND_j.begin(), m_Current_RAND_j.end());
    xres_star_input.insert(xres_star_input.end(), m_Derived_RESj.begin(), m_Derived_RESj.end());
    std::vector<uint8_t> xres_star_j = Kyber::KDF(kran_key, xres_star_input); // Using CK||IK as key
    std::cout << "UAV " << m_Id << ": Calculated XRES*j (size=" << xres_star_j.size() << ")" << std::endl;

    // --- End AKA Steps ---

    // Step 5: Calculate HXRES*j = KDF(KRANj, Cj || XRES*j)
    std::vector<uint8_t> hxres_input = cj;
    hxres_input.insert(hxres_input.end(), xres_star_j.begin(), xres_star_j.end());
    std::vector<uint8_t> hxres_star_j = Kyber::KDF(derived_kran_j, hxres_input);
    std::cout << "UAV " << m_Id << ": Calculated HXRES*j." << std::endl;

    // Authenticate gNB: Compare HRES*j with calculated HXRES*j
    if (hxres_star_j == hres_star_j)
    {
        std::cout << "UAV " << m_Id << ": HRES*j matches HXRES*j. Authenticating gNB." << std::endl;

        // Decrypt Cj using derived KRANj
        std::vector<uint8_t> decrypted_cj = Kyber::DecryptSymmetric(derived_kran_j, cj);

        // Parse TIDj and GKUAV from decrypted_cj
        // Assuming format: [TIDj_bytes][GKUAV_bytes]
        size_t tid_len = 20; // Example fixed length, must match gNB's generation
        if (decrypted_cj.size() > tid_len)
        {
            m_TIDj = Kyber::BytesToString(std::vector<uint8_t>(decrypted_cj.begin(), decrypted_cj.begin() + tid_len));
            m_GKUAV = std::vector<uint8_t>(decrypted_cj.begin() + tid_len, decrypted_cj.end());
            m_KRANj = derived_kran_j; // Store the derived KRANj
            m_IsAuthenticatedWithGNB = true;
            std::cout << "UAV " << m_Id << ": Decrypted Cj. Got TIDj=" << m_TIDj << ", GKUAV (size=" << m_GKUAV.size() << "). Storing keys." << std::endl;

            

            ConfirmServiceAccessAuth(); // Send confirmation back to gNB
        }
        else
        {
            std::cerr << "UAV " << m_Id << ": Error - Decrypted Cj is too short." << std::endl;
            m_IsAuthenticatedWithGNB = false;
        }
    }
    else
    {
        std::cerr << "UAV " << m_Id << ": Error - HRES*j mismatch! Authentication failed." << std::endl;
        m_IsAuthenticatedWithGNB = false;
        // Clear derived keys?
        m_Derived_CKj.clear();
        m_Derived_IKj.clear();
        m_Derived_RESj.clear();
        m_Current_RAND_j.clear();
    }
}

void UAV::ConfirmServiceAccessAuth()
{
    if (auto gnb = GetAssociatedGNBShared())
    {
        std::cout << "UAV " << m_Id << ": Sending Service Access Confirmation to gNB " << gnb->GetID() << std::endl;
        gnb->ReceiveServiceAccessConfirmation(m_Id);
    }
}

// --- UAV-Assisted UE Access Authentication (Phase B) ---

void UAV::ReceiveConnectionRequest(int ueId, const std::vector<uint8_t> &suci_bytes)
{
    std::cout << "UAV " << m_Id << ": Received connection request (SUCI) from UE " << ueId << std::endl;
    if (!m_IsAuthenticatedWithGNB)
    {
        std::cerr << "UAV " << m_Id << ": Not authenticated with gNB. Cannot process UE request." << std::endl;
        // Optionally inform UE of failure
        return;
    }
    if (auto gnb = GetAssociatedGNBShared())
    {
        std::cout << "UAV " << m_Id << ": Forwarding SUCI and TIDj=" << m_TIDj << " to gNB " << gnb->GetID() << std::endl;
        gnb->ProcessUAVAssistedAuthRequest(suci_bytes, m_TIDj, *this, ueId);
    }
}

void UAV::ReceiveUEAuthParams(int ueId,
                              const std::vector<uint8_t> &hres_star_i,
                              const std::vector<uint8_t> &ci,
                              const std::string &tid_i,
                              const std::vector<uint8_t> &kuav_i)
{
    std::cout << "UAV " << m_Id << ": Received UE Auth Params (HRES*i, Ci, TIDi, KUAVi) from gNB for UE " << ueId << "." << std::endl;
    std::cout << "   TIDi=" << tid_i << ", KUAVi size=" << kuav_i.size() << std::endl;

    // Store UE-specific info
    m_ConnectedUEInfo[ueId] = {tid_i, kuav_i};
    std::cout << "UAV " << m_Id << ": Stored TIDi and KUAVi for UE " << ueId << "." << std::endl;

    // Forward (HRES*i, Ci) to UE
    
    auto ue_sp = FindUEById(ueId); // Use virtual function or World lookup
    if (ue_sp)
    {
        std::cout << "UAV " << m_Id << ": Forwarding (HRES*i, Ci) to UE " << ueId << std::endl;
        ue_sp->HandleUAVAssistedAuthResponse(hres_star_i, ci, m_TIDj); // Pass UAV's TIDj too
    }
    else
    {
        std::cerr << "UAV " << m_Id << ": Could not find UE " << ueId << " to forward Auth Params." << std::endl;
        // TODO: Inform gNB?
    }
}

// --- UE Handover Authentication (Phase C) ---

void UAV::ReceiveHandoverAuthRequest(int ueId,
                                     const std::string &tid_i,
                                     const std::vector<uint8_t> &mac_i,
                                     const std::vector<uint8_t> &r1,
                                     const Kyber::Timestamp &tst)
{
    std::cout << "UAV " << m_Id << " (Target): Received Handover Auth Request from UE " << ueId << " (TIDi=" << tid_i << ")" << std::endl;

    if (!m_IsAuthenticatedWithGNB)
    {
        std::cerr << "UAV " << m_Id << ": Not authenticated with gNB. Cannot process handover." << std::endl;
        return;
    }

    // Step 2: Check TST
    if (!Kyber::ValidateTST(tst))
    {
        std::cerr << "UAV " << m_Id << ": Handover failed for UE " << ueId << ". TST is invalid." << std::endl;
        // Inform UE?
        return;
    }
    std::cout << "UAV " << m_Id << ": TST is valid." << std::endl;

    // Compute TGK'i = KDF(GKUAV, TIDi || TST)
    std::vector<uint8_t> tidi_bytes = Kyber::StringToBytes(tid_i);
    std::vector<uint8_t> tst_bytes = Kyber::TimestampToBytes(tst);
    std::vector<uint8_t> tgk_input = tidi_bytes;
    tgk_input.insert(tgk_input.end(), tst_bytes.begin(), tst_bytes.end());
    std::vector<uint8_t> tgk_prime_i = Kyber::KDF(m_GKUAV, tgk_input);
    std::cout << "UAV " << m_Id << ": Computed TGK'i." << std::endl;

    // Compute XMACi = KDF(TGK'i, TID*j || TIDi || R1)
    std::vector<uint8_t> tid_star_j_bytes = Kyber::StringToBytes(m_TIDj); // Target UAV's TID
    std::vector<uint8_t> xmac_input = tid_star_j_bytes;
    xmac_input.insert(xmac_input.end(), tidi_bytes.begin(), tidi_bytes.end());
    xmac_input.insert(xmac_input.end(), r1.begin(), r1.end());
    std::vector<uint8_t> xmac_i = Kyber::KDF(tgk_prime_i, xmac_input);
    std::cout << "UAV " << m_Id << ": Computed XMACi." << std::endl;

    // Check MAC
    if (xmac_i != mac_i)
    {
        std::cerr << "UAV " << m_Id << ": Handover MAC check failed for UE " << ueId << "." << std::endl;
        // Inform UE?
        return;
    }
    std::cout << "UAV " << m_Id << ": MAC check successful." << std::endl;

    // Generate R2
    std::vector<uint8_t> r2 = GenerateRandomBytesUtil(16); // Example size for R2
    std::cout << "UAV " << m_Id << ": Generated R2." << std::endl;

    // Compute RESi = KDF(TGK'i, TID*j || TIDi || R1 || R2)
    std::vector<uint8_t> res_input = xmac_input; // Reuses TID*j || TIDi || R1
    res_input.insert(res_input.end(), r2.begin(), r2.end());
    std::vector<uint8_t> res_i = Kyber::KDF(tgk_prime_i, res_input);
    std::cout << "UAV " << m_Id << ": Computed RESi." << std::endl;

    // Compute K*UAVi = KDF(TGK'i, TID*j || TIDi)
    std::vector<uint8_t> k_star_input = tid_star_j_bytes;
    k_star_input.insert(k_star_input.end(), tidi_bytes.begin(), tidi_bytes.end());
    std::vector<uint8_t> k_star_uav_i = Kyber::KDF(tgk_prime_i, k_star_input);
    std::cout << "UAV " << m_Id << ": Computed K*UAVi." << std::endl;

    // Compute HRESi = KDF(RESi || R2)
    std::vector<uint8_t> hres_input = res_i;
    hres_input.insert(hres_input.end(), r2.begin(), r2.end());
    std::vector<uint8_t> hres_i = Kyber::KDF(hres_input); // Using KDF as a hash here
    std::cout << "UAV " << m_Id << ": Computed HRESi." << std::endl;

    // Store state for verification later
    m_ConnectedUEInfo[ueId] = {tid_i, k_star_uav_i, r1, res_i}; // Store K*, R1, RESi
    std::cout << "UAV " << m_Id << ": Stored K*UAVi, R1, RESi for UE " << ueId << "." << std::endl;

    // Send (HRESi, R2) to UE
    auto ue_sp = FindUEById(ueId);
    if (ue_sp)
    {
        std::cout << "UAV " << m_Id << ": Sending (HRESi, R2) to UE " << ueId << std::endl;
        ue_sp->HandleHandoverAuthChallenge(hres_i, r2);
    }
    else
    {
        std::cerr << "UAV " << m_Id << ": Could not find UE " << ueId << " to send Handover Challenge." << std::endl;
        m_ConnectedUEInfo.erase(ueId); // Clean up state
    }
}

void UAV::ReceiveHandoverAuthConfirmation(int ueId, const std::vector<uint8_t> &xres_i)
{
    std::cout << "UAV " << m_Id << ": Received Handover Auth Confirmation (XRESi) from UE " << ueId << std::endl;

    // Step 4: Check if XRESi matches stored RESi
    if (m_ConnectedUEInfo.count(ueId))
    {
        const auto &ue_info = m_ConnectedUEInfo[ueId];
        if (xres_i == ue_info.expected_res_i)
        {
            std::cout << "UAV " << m_Id << ": XRESi matches RESi. Handover successful for UE " << ueId << "." << std::endl;
            // Store final state (TIDi, K*UAVi) - already stored when RESi was computed
            std::cout << "UAV " << m_Id << ": Stored final state (TIDi, K*UAVi) for UE " << ueId << "." << std::endl;

            // Inform gNB
            if (auto gnb = GetAssociatedGNBShared())
            {
                std::cout << "UAV " << m_Id << ": Sending Handover Inform message to gNB " << gnb->GetID() << " for UE " << ueId << " (TIDi=" << ue_info.tid_i << ")" << std::endl;
                gnb->ReceiveHandoverInform(m_TIDj, ue_info.tid_i);
            }
            // Add UE to connected list (if not already)
            if (auto ue_sp = FindUEById(ueId))
            {
                m_ConnectedUEs[ueId] = ue_sp; // Store weak_ptr
            }
        }
        else
        {
            std::cerr << "UAV " << m_Id << ": Handover confirmation failed for UE " << ueId << ". XRESi mismatch." << std::endl;
            m_ConnectedUEInfo.erase(ueId); // Clean up state
            m_ConnectedUEs.erase(ueId);    // Remove from connected list
        }
    }
    else
    {
        std::cerr << "UAV " << m_Id << ": Received unexpected Handover Confirmation from UE " << ueId << "." << std::endl;
    }
}

// --- General ---

void UAV::BroadcastNotification()
{
    if (m_IsAuthenticatedWithGNB && m_Operational)
    {
        std::cout << "UAV " << m_Id << ": Broadcasting readiness notification (TIDj=" << m_TIDj << ")" << std::endl;
        // In a real simulation, this would trigger nearby UEs
    }
}

// --- Existing Methods Modified/Used ---

// void UAV::SendAuthResponseToUE(int ueId, const std::vector<uint8_t>& res_star) {
//     std::cout << "UAV " << m_Id << ": Forwarding Auth Response (RES*) to UE " << ueId << std::endl;
//     auto ue_sp = FindUEById(ueId);
//     if (ue_sp) {
//         ue_sp->HandleAuthResponse(res_star);
//         m_ConnectedUEs[ueId] = ue_sp; // Store weak_ptr to connected UE
//     } else {
//         std::cerr << "UAV " << m_Id << ": Could not find UE " << ueId << " to forward Auth Response." << std::endl;
//     }
// }

void UAV::SendSyncFailureToUE(int ueId, const std::vector<uint8_t> &auts)
{
    std::cout << "UAV " << m_Id << ": Forwarding Sync Failure (AUTS) to UE " << ueId << std::endl;
    auto ue_sp = FindUEById(ueId);
    if (ue_sp)
    {
        ue_sp->HandleSyncFailure(auts);
    }
    else
    {
        std::cerr << "UAV " << m_Id << ": Could not find UE " << ueId << " to forward Sync Failure." << std::endl;
    }
}

void UAV::SendMacFailureToUE(int ueId)
{
    std::cout << "UAV " << m_Id << ": Forwarding MAC Failure to UE " << ueId << std::endl;
    auto ue_sp = FindUEById(ueId);
    if (ue_sp)
    {
        ue_sp->HandleMacFailure();
    }
    else
    {
        std::cerr << "UAV " << m_Id << ": Could not find UE " << ueId << " to forward MAC Failure." << std::endl;
    }
}

void UAV::ReceiveHandoverRequest(UE &ue, UAV &sourceUAV)
{
    std::cout << "UAV " << m_Id << " (Target): Received handover request for UE " << ue.GetID() << " from UAV " << sourceUAV.GetID() << std::endl;
}

void UAV::NotifyHandoverInitiated(UE &ue, UAV &targetUAV)
{
    std::cout << "UAV " << m_Id << " (Source): Notified that UE " << ue.GetID() << " is handing over to UAV " << targetUAV.GetID() << std::endl;
}

void UAV::ReleaseUE(int ueId)
{
    if (m_ConnectedUEs.count(ueId))
    {
        m_ConnectedUEs.erase(ueId);
        std::cout << "UAV " << m_Id << ": Released connection for UE " << ueId << std::endl;
    }
}

void UAV::ReceiveHandoverConnection(UE &ue)
{
    std::cout << "UAV " << m_Id << ": Receiving handover connection for UE " << ue.GetID() << std::endl;
}

std::vector<int> UAV::GetConnectedUEIds() const
{
    std::vector<int> ueIds;
    for (const auto &pair : m_ConnectedUEs)
    {
        if (auto ue_sp = pair.second.lock())
        {
            ueIds.push_back(pair.first);
        }
    }
    return ueIds;
}

void UAV::SetLongTermKey(const std::string &key)
{
    m_LongTermKey_Kj = key;
    std::cout << "UAV " << m_Id << ": Long term key set." << std::endl;
}
