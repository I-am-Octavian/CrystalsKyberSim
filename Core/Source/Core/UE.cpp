#include "UE.h"
#include <random>
#include <vector>
#include <array>
#include <sstream>
#include <iomanip>

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

void UE::InitiateConnection(UAV& targetUAV)
{
    std::cout << "UE " << m_Id << ": Initiating connection via UAV " << targetUAV.GetID() << std::endl;
    m_UEState = "Connecting";

    // Generate authentication parameters using Kyber algorithm
    auto [suci, other] = GenerateAuthParams();

    std::cout << "UE " << m_Id << ": Generated authentication parameters for connection." << std::endl;

    // Placeholder: Send initial access request to UAV
    // targetUAV.receiveConnectionRequest(*this);
}

void UE::InitiateHandover(UAV& currentUAV, UAV& targetUAV)
{
    std::cout << "UE " << m_Id << ": Initiating handover from UAV " << currentUAV.GetID() << " to UAV " << targetUAV.GetID() << std::endl;
    m_UEState = "Handover";
    // Placeholder: Send handover request to the *target* UAV
    // targetUAV.receiveHandoverRequest(*this, currentUAV);
    // Placeholder: Inform current UAV about handover
    // currentUAV.notifyHandoverInitiated(*this, targetUAV);
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

void UE::ReceiveHandoverCommand(UAV& targetUAV)
{
    std::cout << "UE " << m_Id << ": Received handover command to UAV " << targetUAV.GetID() << std::endl;
    m_UEState = "Handover";
    // Placeholder: Acknowledge command and initiate connection with target UAV
    // targetUAV.receiveHandoverConnection(*this);
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

    // Step 13: Form SUCI = C1 || C2 || MAC || Other
    std::vector<uint8_t> SUCI;
    SUCI.insert(SUCI.end(), C1.begin(), C1.end());
    SUCI.insert(SUCI.end(), C2.begin(), C2.end());
    SUCI.insert(SUCI.end(), MAC.begin(), MAC.end());

    // Other parameters (simplified for this implementation)
    std::vector<uint8_t> other = { 0x01, 0x02, 0x03, 0x04 };
    SUCI.insert(SUCI.end(), other.begin(), other.end());

    // Convert SUCI bytes to a formatted string for display/output
    std::stringstream ss;
    ss << "SUCI:";
    for (const auto& byte : SUCI) {
        ss << " " << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    // Return the SUCI and Other parameters
    return { SUCI, ss.str() };
}

// Define stub implementations of Kyber namespace functions to allow compilation
//namespace Kyber {
//    std::vector<uint8_t> Decompressq(const std::vector<uint8_t>& input, int parameter) {
//        // This is a stub implementation - the real one would be implemented elsewhere
//        return input;
//    }
//
//    std::vector<uint8_t> KDF(const std::vector<uint8_t>& input) {
//        // This is a stub implementation - the real one would be implemented elsewhere
//        return input;
//    }
//
//    std::vector<uint8_t> EMSK(const std::vector<uint8_t>& input) {
//        // This is a stub implementation - the real one would be implemented elsewhere
//        return input;
//    }
//
//    std::vector<uint8_t> f1K(const std::vector<uint8_t>& input) {
//        // This is a stub implementation - the real one would be implemented elsewhere
//        return input;
//    }
//}
