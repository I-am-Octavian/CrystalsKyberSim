#include "Core/World.h"

#include <iostream>
#include <thread>
#include <chrono>

int main() {
    std::cout << "===== 5G Authentication Simulation =====" << std::endl;

    // Create world and setup entities
    World world;

    // Add a gNB (base station) at position (500, 500)
    world.addGNB(1, 500, 500);

    // Add UAVs at different positions
    world.addUAV(101, 300, 300);  // First UAV
    world.addUAV(102, 700, 700);  // Second UAV for handover

    // Add a UE (user equipment) with custom long-term key
    world.addUE(201, 350, 350, "5G_LONG_TERM_KEY");

    // Link entities to allow UAVs to find UEs and vice versa
    world.linkEntities();

    // Setup infrastructure (generate keys, associate UAVs, provision UEs)
    world.setupInfrastructure();

    // Phase A: Authenticate UAVs with the gNB
    std::cout << "\n\n===== PHASE A: UAV Service Authentication =====" << std::endl;
    world.simulateUAVServiceAuthentication(101); // Authenticate first UAV
    std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Allow time for authentication
    world.simulateUAVServiceAuthentication(102); // Authenticate second UAV
    std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Allow time for authentication

    // Phase B: UE connects via an authenticated UAV
    std::cout << "\n\n===== PHASE B: UE Connects via Authenticated UAV =====" << std::endl;
    world.simulateUAVAssistedConnection(201);
    std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Allow time for connection

    // Phase C: UE Handover between authenticated UAVs
    std::cout << "\n\n===== PHASE C: UE Handover Authentication =====" << std::endl;
    world.simulateUEHandoverAuthentication(201, 102);
    std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Allow time for handover

    std::cout << "\n===== 5G Authentication Simulation Complete =====" << std::endl;

    return 0;
}
