#include "UE.h"
#include "KyberUtils.h"
#include <random>
#include <vector>
#include <array>
#include <sstream>
#include <iomanip>
#include <stdexcept>

void UE::SetAuthenticationParameters(const std::string& supi, const std::string& key, const std::vector<uint8_t>& amf, const std::vector<uint8_t>& rho, const Kyber::Polynomial& pk)
{
    m_SUPI = supi;
    m_LongTermKey = key;
    m_AMF = amf;
    m_Rho = rho;
    m_NetworkPK = pk;

    // Assuming Kyber::Matrix A is generated from rho  
    m_A = Kyber::GenerateA(rho);

    std::cout << "Authentication parameters set for UE " << m_Id << std::endl;
}

// Helper to get connected UAV shared_ptr
std::shared_ptr<UAV> UE::GetConnectedUAVShared() const {
    if (auto uav_sp = m_ConnectedUAV.lock()) {
        return uav_sp;
    }
    return nullptr;
}

void UE::InitiateConnection(UAV& targetUAV) {
    std::cout << "UE " << m_Id << ": Initiating connection via UAV " << targetUAV.GetID() << std::endl;
    m_UEState = "Connecting";

    // Step 1 & 2: Generate SUCI = C1 || C2 || MAC
    // GenerateAuthParams calculates these based on Kyber PKE (placeholders)
    // and standard AKA f1K (placeholder).
    // It stores RAND and increments SQN internally.
    auto [suci_bytes, suci_string_for_display] = GenerateAuthParams(); // Assuming this returns the byte vector now

    std::cout << "UE " << m_Id << ": Generated SUCI: " << suci_string_for_display << std::endl;

    // Send SUCI to UAV
    std::cout << "UE " << m_Id << " -> UAV " << targetUAV.GetID() << ": Sending SUCI" << std::endl;
    targetUAV.ReceiveConnectionRequest(m_Id, suci_bytes);
}

void UE::HandleUAVAssistedAuthResponse(const std::vector<uint8_t>& hres_star_i,
                                       const std::vector<uint8_t>& ci,
                                       const std::string& tid_j) { // UAV's TID needed
    std::cout << "UE " << m_Id << ": Received UAV-Assisted Auth Response (HRES*i, Ci) via UAV (TIDj=" << tid_j << ")" << std::endl;

    // Step 6: Calculate HXRES*i and KRANi
    // Need RAND from the initial GenerateAuthParams call.
    // Need K (long term key).
    // Placeholder: Derive KRANi (should use CK/IK derived from K and RAND)
    m_KRANi = Kyber::KDF(Kyber::StringToBytes(m_LongTermKey + "_KRANi"), m_RAND); // Placeholder KRANi
    std::cout << "UE " << m_Id << ": Derived KRANi (size=" << m_KRANi.size() << ")" << std::endl;


    // Placeholder: Calculate RES*i (requires K, RAND, CK, IK)
    std::vector<uint8_t> res_i = Kyber::f2K(m_LongTermKey, m_RAND);
    std::vector<uint8_t> ck = Kyber::f3K(m_LongTermKey, m_RAND);
    std::vector<uint8_t> ik = Kyber::f4K(m_LongTermKey, m_RAND);
    std::vector<uint8_t> ck_ik = Kyber::ConcatBytes({ck, ik});
    std::vector<uint8_t> net_name_bytes = Kyber::StringToBytes("TestNet"); // Assume known or configured
    std::vector<uint8_t> res_star_input = Kyber::ConcatBytes({net_name_bytes, m_RAND, res_i});
    for(size_t i=0; i<res_star_input.size() && i<ck_ik.size(); ++i) res_star_input[i] ^= ck_ik[i];
    std::vector<uint8_t> res_star_i = Kyber::KDF(res_star_input); // This is RES*i
    std::cout << "UE " << m_Id << ": Calculated RES*i." << std::endl;


    // Calculate HXRES*i = KDF(KRANi, Ci || RES*i)
    std::vector<uint8_t> hxres_input = ci;
    hxres_input.insert(hxres_input.end(), res_star_i.begin(), res_star_i.end());
    std::vector<uint8_t> hxres_star_i = Kyber::KDF(m_KRANi, hxres_input);
    std::cout << "UE " << m_Id << ": Calculated HXRES*i." << std::endl;


    // Authenticate network: Check HXRES*i == HRES*i
    if (hxres_star_i != hres_star_i) {
        std::cerr << "UE " << m_Id << ": Network authentication failed! HRES*i mismatch." << std::endl;
        m_UEState = "Failed";
        Disconnect(); // Or specific failure state
        return;
    }
    std::cout << "UE " << m_Id << ": Network authentication successful (HRES*i matches)." << std::endl;

    // Compute TID'i || Token'i = DKRANi(Ci)
    std::vector<uint8_t> decrypted_ci = Kyber::DecryptSymmetric(m_KRANi, ci);
    std::cout << "UE " << m_Id << ": Decrypted Ci (size=" << decrypted_ci.size() << ")" << std::endl;


    // Parse TID'i and Token'i
    // Assuming format: [TIDi_bytes][Tokeni_bytes = TGKi || TST]
    size_t tid_len = 10; // Example fixed length, must match gNB's generation
    size_t tst_len = sizeof(long long); // Timestamp bytes length
    if (decrypted_ci.size() <= tid_len) {
         std::cerr << "UE " << m_Id << ": Error - Decrypted Ci too short to contain TIDi." << std::endl;
         m_UEState = "Failed";
         return;
    }
    m_TIDi = Kyber::BytesToString(std::vector<uint8_t>(decrypted_ci.begin(), decrypted_ci.begin() + tid_len));
    m_Tokeni = std::vector<uint8_t>(decrypted_ci.begin() + tid_len, decrypted_ci.end());
    std::cout << "UE " << m_Id << ": Parsed TID'i=" << m_TIDi << ", Token'i size=" << m_Tokeni.size() << std::endl;


    // Parse TGKi and TST from Token'i
    if (m_Tokeni.size() <= tst_len) {
         std::cerr << "UE " << m_Id << ": Error - Token'i too short to contain TST." << std::endl;
         m_UEState = "Failed";
         return;
    }
    m_TGKi = std::vector<uint8_t>(m_Tokeni.begin(), m_Tokeni.end() - tst_len);
    std::vector<uint8_t> tst_bytes(m_Tokeni.end() - tst_len, m_Tokeni.end());
    m_TST = Kyber::BytesToTimestamp(tst_bytes);
    std::cout << "UE " << m_Id << ": Parsed TGKi (size=" << m_TGKi.size() << ") and TST." << std::endl;

    // Validate TST
    if (!Kyber::ValidateTST(m_TST)) {
         std::cerr << "UE " << m_Id << ": Error - Received TST is invalid/expired." << std::endl;
         m_UEState = "Failed";
         return;
    }
     std::cout << "UE " << m_Id << ": TST is valid." << std::endl;


    // Update SQNi = SQNi + 1 (already done in GenerateAuthParams)

    // Compute KUAVi = KDF(KRANi, TID'i || TIDj)
    std::vector<uint8_t> tidi_bytes = Kyber::StringToBytes(m_TIDi);
    std::vector<uint8_t> tidj_bytes = Kyber::StringToBytes(tid_j);
    std::vector<uint8_t> kuavi_input = tidi_bytes;
    kuavi_input.insert(kuavi_input.end(), tidj_bytes.begin(), tidj_bytes.end());
    m_KUAVi = Kyber::KDF(m_KRANi, kuavi_input);
    std::cout << "UE " << m_Id << ": Computed KUAVi (size=" << m_KUAVi.size() << ")" << std::endl;


    // Store (TID'i, KUAVi, Token'i)
    std::cout << "UE " << m_Id << ": Storing TIDi, KUAVi, Tokeni." << std::endl;

    // Transmit access confirmation message to gNB (via UAV)
    std::cout << "UE " << m_Id << ": (Placeholder) Sending Access Confirmation message." << std::endl;
    // This step isn't fully detailed, might involve sending TIDi or similar back.

    // Update state to Connected
    // Need to get shared_ptr to the UAV somehow (passed in or looked up)
    // ConfirmConnection(find_uav_somehow(tid_j), find_gnb_somehow()); // Update connection state
     m_UEState = "Connected"; // Simplified state update
     std::cout << "UE " << m_Id << ": Authentication successful. State set to Connected." << std::endl;


}

void UE::InitiateHandoverAuthentication(UAV& targetUAV) {
    std::cout << "UE " << m_Id << ": Initiating Handover Authentication with Target UAV " << targetUAV.GetID() << " (TID*j=" << targetUAV.GetTID() << ")" << std::endl;

    if (m_UEState != "Connected" || m_TIDi.empty() || m_TGKi.empty() || !Kyber::ValidateTST(m_TST)) {
        std::cerr << "UE " << m_Id << ": Cannot initiate handover. Not connected or missing required state (TIDi, TGKi, valid TST)." << std::endl;
        return;
    }

    m_UEState = "Handover";
    m_Handover_TargetTIDj = targetUAV.GetTID();
    m_Handover_TargetUAV = targetUAV.GetSelfPtr(); // Need a way for UAV to provide its shared_ptr

    // Step 1: Generate R1, compute MACi
    m_Handover_R1 = GenerateRandomBytes(16); // Example size for R1
    std::cout << "UE " << m_Id << ": Generated R1 for handover." << std::endl;


    // MACi = KDF(TGKi, TID*j || TIDi || R1)
    std::vector<uint8_t> tid_star_j_bytes = Kyber::StringToBytes(m_Handover_TargetTIDj);
    std::vector<uint8_t> tidi_bytes = Kyber::StringToBytes(m_TIDi);
    std::vector<uint8_t> mac_input = tid_star_j_bytes;
    mac_input.insert(mac_input.end(), tidi_bytes.begin(), tidi_bytes.end());
    mac_input.insert(mac_input.end(), m_Handover_R1.begin(), m_Handover_R1.end());
    std::vector<uint8_t> mac_i = Kyber::KDF(m_TGKi, mac_input);
    std::cout << "UE " << m_Id << ": Computed MACi for handover." << std::endl;


    // Transmit (TIDi, MACi, R1, TST) to target UAV
    std::cout << "UE " << m_Id << " -> Target UAV " << targetUAV.GetID() << ": Sending Handover Auth Request (TIDi, MACi, R1, TST)" << std::endl;
    targetUAV.ReceiveHandoverAuthRequest(m_Id, m_TIDi, mac_i, m_Handover_R1, m_TST);
}

void UE::HandleHandoverAuthChallenge(const std::vector<uint8_t>& hres_i,
                                     const std::vector<uint8_t>& r2) {
    std::cout << "UE " << m_Id << ": Received Handover Auth Challenge (HRESi, R2) from Target UAV " << m_Handover_TargetTIDj << std::endl;

    if (m_UEState != "Handover" || m_Handover_R1.empty() || m_Handover_TargetTIDj.empty()) {
         std::cerr << "UE " << m_Id << ": Received unexpected Handover Challenge or missing state." << std::endl;
         return;
    }

    // Step 3: Compute XRESi, HXRESi
    // XRESi = KDF(TGKi, TID*j || TIDi || R1 || R2)
    std::vector<uint8_t> tid_star_j_bytes = Kyber::StringToBytes(m_Handover_TargetTIDj);
    std::vector<uint8_t> tidi_bytes = Kyber::StringToBytes(m_TIDi);
    std::vector<uint8_t> xres_input = tid_star_j_bytes;
    xres_input.insert(xres_input.end(), tidi_bytes.begin(), tidi_bytes.end());
    xres_input.insert(xres_input.end(), m_Handover_R1.begin(), m_Handover_R1.end());
    xres_input.insert(xres_input.end(), r2.begin(), r2.end());
    std::vector<uint8_t> xres_i = Kyber::KDF(m_TGKi, xres_input);
    std::cout << "UE " << m_Id << ": Computed XRESi." << std::endl;


    // HXRESi = KDF(XRESi || R2)
    std::vector<uint8_t> hxres_input = xres_i;
    hxres_input.insert(hxres_input.end(), r2.begin(), r2.end());
    std::vector<uint8_t> hxres_i = Kyber::KDF(hxres_input); // Using KDF as hash
    std::cout << "UE " << m_Id << ": Computed HXRESi." << std::endl;


    // Check HXRESi == HRESi
    if (hxres_i != hres_i) {
        std::cerr << "UE " << m_Id << ": Handover authentication failed! HRESi mismatch." << std::endl;
        m_UEState = "Connected"; // Revert state? Or FailedHandover?
        m_Handover_R1.clear();
        m_Handover_TargetTIDj = "";
        m_Handover_TargetUAV.reset();
        return;
    }
    std::cout << "UE " << m_Id << ": Handover authentication successful (HRESi matches)." << std::endl;

    // Compute K*UAVi = KDF(TGKi, TID*j || TIDi)
    std::vector<uint8_t> k_star_input = tid_star_j_bytes;
    k_star_input.insert(k_star_input.end(), tidi_bytes.begin(), tidi_bytes.end());
    std::vector<uint8_t> k_star_uav_i = Kyber::KDF(m_TGKi, k_star_input);
    std::cout << "UE " << m_Id << ": Computed K*UAVi (new KUAVi)." << std::endl;


    // Store K*UAVi (replace old KUAVi)
    m_KUAVi = k_star_uav_i;
    std::cout << "UE " << m_Id << ": Stored new KUAVi." << std::endl;


    // Transmit XRESi to target UAV
    if (auto targetUAV = m_Handover_TargetUAV.lock()) {
        std::cout << "UE " << m_Id << " -> Target UAV " << targetUAV->GetID() << ": Sending Handover Auth Confirmation (XRESi)" << std::endl;
        targetUAV->ReceiveHandoverAuthConfirmation(m_Id, xres_i);

        // Update connection state
        m_ConnectedUAV = targetUAV; // Point to new UAV
        m_ServingUAVId = targetUAV->GetID();
        // gNB connection likely remains the same
        m_UEState = "Connected";
        std::cout << "UE " << m_Id << ": Handover to UAV " << m_ServingUAVId << " completed." << std::endl;

    } else {
         std::cerr << "UE " << m_Id << ": Target UAV pointer invalid. Cannot complete handover." << std::endl;
         m_UEState = "Connected"; // Revert state?
    }

    // Clear handover state
    m_Handover_R1.clear();
    m_Handover_TargetTIDj = "";
    m_Handover_TargetUAV.reset();
}

void UE::ConfirmConnection(std::shared_ptr<UAV> uav, std::shared_ptr<gNB> gnb)
{
    m_ConnectedUAV = uav;
    m_ConnectedgNB = gnb;
    m_ServingUAVId = uav->GetID();
    m_ServingGNBId = gnb->GetID();
    m_UEState = "Connected";
    std::cout << "UE " << m_Id << ": Connection established via UAV " << m_ServingUAVId << " to gNB " << m_ServingGNBId << std::endl;
}

void UE::ConfirmHandover(std::shared_ptr<UAV> newUAV)
{
    m_ConnectedUAV = newUAV;
    m_ServingUAVId = newUAV->GetID();
    // gNB connection usually remains the same unless gNB also changes
    m_UEState = "Connected";
    std::cout << "UE " << m_Id << ": Handover to UAV " << m_ServingUAVId << " completed." << std::endl;
}


void UE::Disconnect()
{
    m_ConnectedUAV.reset();
    m_ConnectedgNB.reset();
    m_ServingUAVId = -1;
    m_ServingGNBId = -1;
    m_UEState = "Idle";
    std::cout << "UE " << m_Id << ": Disconnected." << std::endl;
}

void UE::HandleSyncFailure(const std::vector<uint8_t>& auts)
{
}

void UE::HandleMacFailure()
{
}

// Generate random bytes for RAND value
std::vector<uint8_t> UE::GenerateRandomBytes(size_t numBytes)
{
    std::vector<uint8_t> bytes(numBytes);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 255);

    for (size_t i = 0; i < numBytes; ++i) {
        bytes[i] = static_cast<uint8_t>(distrib(gen));
    }

    return bytes;
}

// Sample from B3 distribution for Kyber
Kyber::Polynomial UE::SampleB3(size_t size)
{
    // Simplified implementation - in a real-world case, this would use 
    // the actual B3 distribution from Kyber
    Kyber::Polynomial result(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(-3, 3);  // B3 distribution range

    for (size_t i = 0; i < size; ++i) {
        result[i] = distrib(gen);
    }

    return result;
}

// Sample from B2 distribution for Kyber
Kyber::Polynomial UE::SampleB2(size_t size)
{
    // Simplified implementation - in a real-world case, this would use 
    // the actual B2 distribution from Kyber
    Kyber::Polynomial result(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(-2, 2);  // B2 distribution range

    for (size_t i = 0; i < size; ++i) {
        result[i] = distrib(gen);
    }

    return result;
}

// Generate authentication parameters using Kyber algorithm
std::pair<std::vector<uint8_t>, std::string> UE::GenerateAuthParams()
{
    // Step 1: Generate a random value RAND ∈ {0, 1}^256
    m_RAND = GenerateRandomBytes(32); // 32 bytes = 256 bits

    // Step 2: Generate a fresh sequence number SQN
    m_SQN++;

    // Step 3: Sample r ∈ R^2_q from B3
    const size_t polynomialSize = 256; // Size depends on Kyber specification
    const int q = 3329;  // Kyber's q value
    auto r = SampleB3(polynomialSize);

    // Step 4: Sample e1 ∈ R^2_q from B2
    auto e1 = SampleB2(polynomialSize);

    // Step 5: Sample e2 ∈ R_q from B2
    auto e2 = SampleB2(polynomialSize / 2);

    // Step 6: Compute u = A^T * r + e1
    // This is a simplified placeholder - in a real implementation,
    // A would be a public matrix from Kyber parameters
    std::vector<uint8_t> u(polynomialSize); // Simplified placeholder

    // Step 7: Compute v = pk^T * r + e2 + Decompressq(RAND, 1)
    // This is a simplified placeholder - in a real implementation,
    // pk would be the public key from the network
    std::vector<int> decompressed;
    try {
        // Assuming Kyber::Decompressq is implemented elsewhere
        decompressed = Kyber::Decompressq(m_RAND, 1);
    }
    catch (...) {
        // Fallback for compilation if the actual function is not available
        decompressed = { 0 };
        std::cout << "Warning: Using placeholder implementation for Decompressq" << std::endl;
    }

    std::vector<uint8_t> v(polynomialSize / 2); // Simplified placeholder

    // Step 8: Compute C1 = (u, v)
    std::vector<uint8_t> C1;
    C1.insert(C1.end(), u.begin(), u.end());
    C1.insert(C1.end(), v.begin(), v.end());

    // Step 9: Compute MSK = KDF(RAND)
    std::vector<uint8_t> MSK;
    try {
        // Assuming Kyber::KDF is implemented elsewhere
        MSK = Kyber::KDF(m_RAND);
    }
    catch (...) {
        // Fallback for compilation if the actual function is not available
        MSK = m_RAND;
        std::cout << "Warning: Using placeholder implementation for KDF" << std::endl;
    }

    // Step 10: Convert SQN to bytes for further operations
    std::vector<uint8_t> sqnBytes(8);
    for (int i = 0; i < 8; ++i) {
        sqnBytes[i] = static_cast<uint8_t>((m_SQN >> (i * 8)) & 0xFF);
    }

    // Step 11: Compute C2 = EMSK(SUPI || SQNUE)
    std::string SUPI = "SUPI_" + std::to_string(m_Id); // Example SUPI
    m_SUPI = SUPI;

    std::vector<uint8_t> supiBytes(SUPI.begin(), SUPI.end());
    std::vector<uint8_t> supiAndSqn;
    supiAndSqn.insert(supiAndSqn.end(), supiBytes.begin(), supiBytes.end());
    supiAndSqn.insert(supiAndSqn.end(), sqnBytes.begin(), sqnBytes.end());

    std::vector<uint8_t> C2;
    try {
        // Assuming Kyber::EMSK is implemented elsewhere
        C2 = Kyber::EMSK(supiAndSqn);
    }
    catch (...) {
        // Fallback for compilation if the actual function is not available
        C2 = supiAndSqn;
        std::cout << "Warning: Using placeholder implementation for EMSK" << std::endl;
    }

    // Step 12: Compute MAC = f1K(SQNUE || RAND || AMF)
    // For simplicity, AMF (Authentication Management Field) is fixed here
    std::vector<uint8_t> AMF = { 0x00, 0x00 };

    std::vector<uint8_t> macInput;
    macInput.insert(macInput.end(), sqnBytes.begin(), sqnBytes.end());
    macInput.insert(macInput.end(), m_RAND.begin(), m_RAND.end());
    macInput.insert(macInput.end(), AMF.begin(), AMF.end());

    std::vector<uint8_t> MAC;
    try {
        // Assuming Kyber::f1K is implemented elsewhere
        MAC = Kyber::f1K(m_LongTermKey ,macInput);
    }
    catch (...) {
        // Fallback for compilation if the actual function is not available
        MAC = macInput;
        std::cout << "Warning: Using placeholder implementation for f1K" << std::endl;
    }

    // Step 13: Form SUCI = C1 || C2 || MAC
    std::vector<uint8_t> SUCI_bytes;
    SUCI_bytes.insert(SUCI_bytes.end(), C1.begin(), C1.end());
    SUCI_bytes.insert(SUCI_bytes.end(), C2.begin(), C2.end());
    SUCI_bytes.insert(SUCI_bytes.end(), MAC.begin(), MAC.end());

    // Convert SUCI bytes to a formatted string for display/output
    std::stringstream ss;
    ss << "SUCI(Hex):";
    for (const auto& byte : SUCI_bytes) {
        ss << " " << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    // Return the SUCI bytes and the display string
    return { SUCI_bytes, ss.str() };
}
