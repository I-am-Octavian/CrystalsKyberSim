#pragma once

#include "UE.h"
#include "gNB.h"
#include "UAV.h"
#include <limits> // Include limits for numeric_limits
#include <stdexcept> // For exceptions
#include <string> // Ensure string is included

class World {
public:
    std::vector<std::shared_ptr<UE>> ues;
    std::vector<std::shared_ptr<UAV>> uavs;
    std::vector<std::shared_ptr<gNB>> gnbs;

    void addUE(uint32_t id, uint32_t x, uint32_t y, const std::string& longTermKey = "DEFAULT_KEY") {
        ues.push_back(std::make_shared<UE>(x, y, 0, 0, id, longTermKey));
        std::cout << "World: Added UE " << id << " at (" << x << ", " << y << ")" << std::endl;
    }

    void addUAV(uint32_t id, uint32_t x, uint32_t y) {
        uavs.push_back(std::make_shared<UAV>(x, y, 0, 0, id));
        std::cout << "World: Added UAV " << id << " at (" << x << ", " << y << ")" << std::endl;
    }

    void addGNB(uint32_t id, uint32_t x, uint32_t y) {
        gnbs.push_back(std::make_shared<gNB>(x, y, 0, 0, id));
        std::cout << "World: Added gNB " << id << " at (" << x << ", " << y << ")" << std::endl;
    }

    // Associate UAVs with the nearest gNB
    void setupAssociations() {
        if (gnbs.empty()) {
            std::cerr << "Warning: No gNBs in the world to associate UAVs with." << std::endl;
            return;
        }
        for (auto& uav : uavs) {
            std::shared_ptr<gNB> nearestGNB = gnbs[0];
            uint32_t minDistance = std::numeric_limits<uint32_t>::max();

            for (auto& gnb : gnbs) {
                uint32_t dx = uav->GetPosition().first - gnb->GetPosition().first;
                uint32_t dy = uav->GetPosition().second - gnb->GetPosition().second;
                uint32_t distSq = dx * dx + dy * dy;
                if (distSq < minDistance) {
                    minDistance = distSq;
                    nearestGNB = gnb;
                }
            }
            std::cout << "World: Associating UAV " << uav->GetID() << " with gNB " << nearestGNB->GetID() << std::endl;
            nearestGNB->RegisterUAV(uav);
        }
    }

    // Provision UEs with necessary parameters from their associated gNB
    void provisionUEs() {
        std::cout << "World: Provisioning UEs..." << std::endl;
        if (gnbs.empty()) {
            std::cerr << "Warning: No gNBs to provision from." << std::endl;
            return;
        }
        auto provisioningGNB = gnbs[0];
        const auto& pk = provisioningGNB->GetKyberPublicKey();
        const auto& rho = provisioningGNB->GetKyberRho();
        const auto& amf = provisioningGNB->GetAMF();

        for (auto& ue : ues) {
            std::string supi = "SUPI_UE" + std::to_string(ue->GetID());
            std::string key = ue->GetLongTermKey();

            provisioningGNB->ProvisionUEKey(supi, key);
            ue->SetAuthenticationParameters(supi, key, amf, rho, pk);
            std::cout << "World: Provisioned UE " << ue->GetID() << " with SUPI " << supi << std::endl;
        }
        std::cout << "World: UE provisioning complete." << std::endl;
    }

    void provisionUAVs() {
        std::cout << "\n--- Provisioning UAV Keys ---" << std::endl;
        if (gnbs.empty()) {
            std::cerr << "World Error: No gNBs to provision UAVs." << std::endl;
            return;
        }
        auto gnb = gnbs[0]; // Assume one gNB

        for (auto& uav : uavs) {
            // Simple key generation for simulation: "UAV_KEY_" + ID
            std::string uav_key = "UAV_KEY_" + std::to_string(uav->GetID());
            uav->SetLongTermKey(uav_key);
            gnb->ProvisionUAVKey(uav->GetID(), uav_key);
        }
        std::cout << "--- UAV Key Provisioning Complete ---" << std::endl;
    }

    void setupInfrastructure() {
        std::cout << "\n--- Setting up Infrastructure ---" << std::endl;
        if (gnbs.empty()) {
             std::cerr << "World Error: No gNBs defined." << std::endl;
             return;
        }
        auto gnb = gnbs[0];
        gnb->GenerateGroupKey(); // Generate GKUAV
        provisionUAVs(); // Provision UAV keys
        setupAssociations(); // Associate UAVs
        provisionUEs(); // Provision UEs with gNB params
        std::cout << "--- Infrastructure Setup Complete ---" << std::endl;
    }

    // --- Simulation Scenarios ---

    // Phase A: Authenticate a UAV with the gNB
    void simulateUAVServiceAuthentication(int uavId) {
         std::cout << "\n--- Simulating UAV Service Authentication for UAV " << uavId << " ---" << std::endl;
         auto uav = findUAV(uavId);
         if (!uav) {
             std::cerr << "World Error: UAV " << uavId << " not found." << std::endl;
             return;
         }

         uav->DoUAVAccessAuth();
         // The rest of Phase A happens via callbacks between gNB and UAV
         
    }

    // Phase B: UE connects via an authenticated UAV
    void simulateUAVAssistedConnection(int ueId) {
        std::cout << "\n--- Simulating UAV-Assisted Connection for UE " << ueId << " ---" << std::endl;
        auto ue = findUE(ueId);
        if (!ue) {
            std::cerr << "World Error: UE " << ueId << " not found." << std::endl;
            return;
        }

        // Find nearest *authenticated* and operational UAV
        auto targetUAV = findNearestAuthenticatedUAV(ue->GetPosition());
        if (targetUAV) {
            std::cout << "World: UE " << ueId << " found nearest authenticated UAV " << targetUAV->GetID() << " (TIDj=" << targetUAV->GetTID() << ")" << std::endl;
            ue->InitiateConnection(*targetUAV);
            // Note: The rest of Phase B happens via callbacks: UE -> UAV -> gNB -> UAV -> UE
        } else {
            std::cerr << "World Error: No available authenticated UAV found for UE " << ueId << std::endl;
        }
    }

    // Phase C: UE Handover between authenticated UAVs
    void simulateUEHandoverAuthentication(int ueId, int targetUavId) {
         std::cout << "\n--- Simulating UE Handover Authentication for UE " << ueId << " to UAV " << targetUavId << " ---" << std::endl;
         auto ue = findUE(ueId);
         auto targetUAV = findUAV(targetUavId);

         if (!ue) {
             std::cerr << "World Error: UE " << ueId << " not found." << std::endl;
             return;
         }
         if (!targetUAV) {
              std::cerr << "World Error: Target UAV " << targetUavId << " not found." << std::endl;
              return;
         }
         if (!targetUAV->IsOperational() || !targetUAV->IsAuthenticatedWithGNB()) {
             std::cerr << "World Error: Target UAV " << targetUavId << " is not operational or not authenticated." << std::endl;
             return;
         }
         if (ue->GetServingUAVId() == targetUavId) {
              std::cerr << "World Error: UE " << ueId << " already connected to target UAV " << targetUavId << "." << std::endl;
              return;
         }

         // Check if UE has necessary state from Phase B
         // (Simplified check - just see if state is Connected)
         if (ue->GetState() != "Connected") {
              std::cerr << "World Error: UE " << ueId << " is not in Connected state. Cannot initiate handover auth." << std::endl;
              return;
         }


         ue->InitiateHandoverAuthentication(*targetUAV);
         // Note: The rest of Phase C happens via callbacks: UE -> TargetUAV -> UE -> TargetUAV -> gNB
    }

    // --- Helper Methods ---
    std::shared_ptr<UE> findUE(int id) {
        for (auto& ue : ues) {
            if (ue->GetID() == id) return ue;
        }
        return nullptr;
    }

    std::shared_ptr<UAV> findUAV(int id) {
        for (auto& uav : uavs) {
            if (uav->GetID() == id) return uav;
        }
        return nullptr;
    }

    std::shared_ptr<gNB> findGNB(int id) {
        for (auto& gnb : gnbs) {
            if (gnb->GetID() == id) return gnb;
        }
        return nullptr;
    }

    std::shared_ptr<UAV> findNearestAvailableUAV(const Position& pos) {
        std::shared_ptr<UAV> bestUAV = nullptr;
        uint32_t minDistSq = std::numeric_limits<uint32_t>::max();

        for (auto& uav : uavs) {
            if (uav->IsOperational()) {
                uint32_t dx = uav->GetPosition().first - pos.first;
                uint32_t dy = uav->GetPosition().second - pos.second;
                uint32_t distSq = dx * dx + dy * dy;
                if (distSq < minDistSq) {
                    minDistSq = distSq;
                    bestUAV = uav;
                }
            }
        }
        return bestUAV;
    }

    std::shared_ptr<UAV> findNearestAuthenticatedUAV(const Position& pos) {
        std::shared_ptr<UAV> bestUAV = nullptr;
        uint32_t minDistSq = std::numeric_limits<uint32_t>::max();

        for (auto& uav : uavs) {
            // Check operational status AND if authenticated with gNB
            if (uav->IsOperational() && uav->IsAuthenticatedWithGNB()) {
                uint32_t dx = uav->GetPosition().first - pos.first;
                uint32_t dy = uav->GetPosition().second - pos.second;
                uint32_t distSq = dx * dx + dy * dy;
                if (distSq < minDistSq) {
                    minDistSq = distSq;
                    bestUAV = uav;
                }
            }
        }
        return bestUAV;
    }

    std::shared_ptr<UAV> findBestAlternativeUAVForGNB(const Position& uePos, int failedUavId, std::shared_ptr<gNB> gnb) {
        std::shared_ptr<UAV> bestUAV = nullptr;
        uint32_t minDistSq = std::numeric_limits<uint32_t>::max();

        for (auto& uav : uavs) {
            if (uav->GetID() != failedUavId && uav->IsOperational()) {
                bool associated = false;
                if (auto assoc_gnb = uav->GetAssociatedGNB().lock()) {
                    if (assoc_gnb->GetID() == gnb->GetID()) associated = true;
                }

                uint32_t dx = uav->GetPosition().first - uePos.first;
                uint32_t dy = uav->GetPosition().second - uePos.second;
                uint32_t distSq = dx * dx + dy * dy;
                if (distSq < minDistSq) {
                    minDistSq = distSq;
                    bestUAV = uav;
                }
            }
        }
        return bestUAV;
    }

    void update(float deltaTime) {
        for (auto& ue : ues) { ue->Update(deltaTime); }
        for (auto& uav : uavs) { uav->Update(deltaTime); }
        for (auto& gnb : gnbs) { gnb->Update(deltaTime); }
    }

    std::vector<std::pair<std::string, Position>> getAllEntityPositions() const {
        std::vector<std::pair<std::string, Position>> positions;
        for (const auto& ue : ues) { positions.push_back({ ue->GetType() + std::to_string(ue->GetID()), ue->GetPosition() }); }
        for (const auto& uav : uavs) { positions.push_back({ uav->GetType() + std::to_string(uav->GetID()), uav->GetPosition() }); }
        for (const auto& gnb : gnbs) { positions.push_back({ gnb->GetType() + std::to_string(gnb->GetID()), gnb->GetPosition() }); }
        return positions;
    }

    void linkEntities() {
        std::cout << "World: Linking entities..." << std::endl;
        for(auto& uav : uavs) {
            // Hacky way to allow UAV to find UEs - inject find function
            uav->findUEHandler = [this](int ueId) { return this->findUE(ueId); };
            // Hacky way to allow UAV to get shared_ptr to itself
            uav->getSelfPtrHandler = [uav]() { return uav; };
        }
         // Similar linking could be done for UE finding UAVs if needed
         std::cout << "World: Entity linking complete." << std::endl;
    }
};
