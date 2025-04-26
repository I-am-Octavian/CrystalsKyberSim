#pragma once

#include <cstdint>
#include <utility>
#include <string>

using Position = std::pair<uint32_t, uint32_t>;
using Velocity = std::pair<uint32_t, uint32_t>;

class Entity
{
public:
	Entity() = default;
	Entity(uint32_t theXCoord, uint32_t theYCoord, 
		uint32_t theXVel = 0, uint32_t theYVel = 0, uint32_t theId = 0)
		: m_Position(theXCoord, theYCoord), m_Velocity(theXVel, theYVel), m_Id(theId) {}

	inline Position GetPosition() const { return m_Position; }

	inline void SetPosition(uint32_t theX, uint32_t theY)
	{
		m_Position = { theX, theY };
	}

	inline uint32_t GetID() const { return m_Id; }

	virtual std::string GetType() const = 0;

	virtual void Update(float deltaTime) {
		m_Position.first += static_cast<uint32_t>(m_Velocity.first * deltaTime);
		m_Position.second += static_cast<uint32_t>(m_Velocity.second * deltaTime);
	}

protected:
	Position m_Position{};
	Velocity m_Velocity{};
	uint32_t m_Id{};
};