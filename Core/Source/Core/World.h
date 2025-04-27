#pragma once

#include "UE.h"
#include "gNB.h"
#include "UAV.h"
#include <limits> // Include limits for numeric_limits

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
            float minDistance = std::numeric_limits<float>::max();

            for (auto& gnb : gnbs) {
                float dx = uav->GetPosition().first - gnb->GetPosition().first;
                float dy = uav->GetPosition().second - gnb->GetPosition().second;
                float distSq = dx * dx + dy * dy;
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

    // --- Simulation Scenario Placeholders ---

    void simulateInitialConnection(int ueId) {
        auto ue = findUE(ueId);
        if (!ue) {
            std::cerr << "UE " << ueId << " not found." << std::endl;
            return;
        }

        auto targetUAV = findNearestAvailableUAV(ue->GetPosition());
        if (targetUAV) {
            std::cout << "\n--- Simulating Initial Connection for UE " << ueId << " ---" << std::endl;

            std::cout << "UE " << ueId << " -> UAV " << targetUAV->GetID() << ": Authentication Request (SUCI)" << std::endl;
            ue->InitiateConnection(*targetUAV);
        } else {
            std::cerr << "No available UAV found for UE " << ueId << std::endl;
        }
    }

    void simulateUEInitiatedHandover(int ueId, int targetUavId) {
        auto ue = findUE(ueId);
        auto targetUAV = findUAV(targetUavId);
        if (!ue || !targetUAV) {
            std::cerr << "UE or Target UAV not found." << std::endl;
            return;
        }
        if (!targetUAV->IsOperational()) {
            std::cerr << "Target UAV " << targetUavId << " is not operational." << std::endl;
            return;
        }

        auto currentUAV = findUAV(ue->GetServingUAVId());
        if (!currentUAV) {
            std::cerr << "UE " << ueId << " is not connected or current UAV not found." << std::endl;
            return;
        }

        std::cout << "\n--- Simulating UE-Initiated Handover for UE " << ueId << " to UAV " << targetUavId << " ---" << std::endl;
        currentUAV->ReleaseUE(ueId);
        ue->ConfirmHandover(targetUAV);
    }

    void simulateUAVFailureHandover(int failedUavId) {
        auto failedUAV = findUAV(failedUavId);
        if (!failedUAV) {
            std::cerr << "UAV " << failedUavId << " not found." << std::endl;
            return;
        }
        if (!failedUAV->IsOperational()) {
            std::cerr << "UAV " << failedUavId << " already not operational." << std::endl;
            return;
        }

        std::cout << "\n--- Simulating UAV Failure Handover for UAV " << failedUavId << " ---" << std::endl;
        failedUAV->SetOperationalStatus(false);

        std::shared_ptr<gNB> responsibleGNB = nullptr;
        for (const auto& gnb : gnbs) {
            responsibleGNB = gnb;
            break;
        }

        if (responsibleGNB) {
            auto affectedUEIds = failedUAV->GetConnectedUEIds();
            std::cout << "   gNB " << responsibleGNB->GetID() << " handling failure for UAV " << failedUavId << ". Affected UEs: ";
            for (int id : affectedUEIds) std::cout << id << " ";
            std::cout << std::endl;

            for (int ueId : affectedUEIds) {
                auto ue = findUE(ueId);
                if (!ue) continue;

                auto targetUAV = findBestAlternativeUAVForGNB(ue->GetPosition(), failedUavId, responsibleGNB);

                if (targetUAV) {
                    std::cout << "   gNB instructing UE " << ueId << " to handover to UAV " << targetUAV->GetID() << std::endl;
                    failedUAV->ReleaseUE(ueId);
                    ue->ConfirmHandover(targetUAV);
                } else {
                    std::cout << "   gNB could not find alternative UAV for UE " << ueId << ". Disconnecting." << std::endl;
                    ue->Disconnect();
                    failedUAV->ReleaseUE(ueId);
                }
            }
        } else {
            std::cerr << "No gNB found to handle UAV " << failedUavId << " failure." << std::endl;
            auto affectedUEIds = failedUAV->GetConnectedUEIds();
            for (int ueId : affectedUEIds) {
                auto ue = findUE(ueId);
                if (ue) ue->Disconnect();
            }
        }
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
        float minDistSq = std::numeric_limits<float>::max();

        for (auto& uav : uavs) {
            if (uav->IsOperational()) {
                float dx = uav->GetPosition().first - pos.first;
                float dy = uav->GetPosition().second - pos.second;
                float distSq = dx * dx + dy * dy;
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
        float minDistSq = std::numeric_limits<float>::max();

        for (auto& uav : uavs) {
            if (uav->GetID() != failedUavId && uav->IsOperational()) {
                bool associated = false;
                if (auto assoc_gnb = uav->GetAssociatedGNB().lock()) {
                    if (assoc_gnb->GetID() == gnb->GetID()) associated = true;
                }

                float dx = uav->GetPosition().first - uePos.first;
                float dy = uav->GetPosition().second - uePos.second;
                float distSq = dx * dx + dy * dy;
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
};
