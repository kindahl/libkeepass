/*
 * libkeepass - KeePass key database importer/exporter
 * Copyright (C) 2014 Christian Kindahl
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once
#include <algorithm>
#include <array>
#include <ctime>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace keepass {

/**
 * Clamps a value into a specific range.
 * @param [in] min Minimum value.
 * @param [in] max Maximum value.
 * @param [in] val Value to clamp.
 * @return Clamped @a val.
 */
template <typename T>
inline T clamp(T min, T max, T val) {
  return std::max<T>(min, std::min<T>(max, val));
}

/**
 * Compares the elements in two vectors for equality. This function is designed
 * for vectors containing pointer types and will dereference each element
 * before comparison.
 * @param [in] v0 First vector.
 * @param [in] v1 Second vector.
 * @return true if all (dereferenced) elements of @a v1 and @a v2 are equal.
 *         If not, the function returns false.
 */
template <typename T>
inline bool indirect_equal(const std::vector<T>& v0,
                           const std::vector<T>& v1) {
  return std::equal(v0.begin(), v0.end(), v1.begin(),
      [](const T& v0, const T& v1) {
        return *v0 == *v1;
      });
}

/**
 * Compares the elements of two pointers for equality. This function will
 * dereference each pointer as necessary in order to test equality by value.
 * @param [in] p0 Pointer to first element.
 * @param [in] p1 Pointer to second element.
 * @return true if the elements of both dereferenced pointers are equal or if
 *         both pointers are null. false is returned otherwise.
 */
template <typename T>
inline bool indirect_equal(std::shared_ptr<T> p0, std::shared_ptr<T> p1) {
  if (p0 != nullptr && p1 != nullptr)
    return *p0 == *p1;

  return p0 == nullptr && p1 == nullptr;
}

/**
 * Visits graph nodes in depth-first order. The first root node will not be
 * visited.
 * @tparam T Node type.
 * @tparam F Function of @a T that will return a vector with all children.
 * @param [in] current Start node.
 * @param [in] callback Function to be called for each visited node.
 */
template <typename T, const std::vector<std::shared_ptr<T>>& (T::*F)() const>
inline void dfs(const std::shared_ptr<T>& current,
                std::function<void(const std::shared_ptr<T>&,
                                   std::size_t)> callback,
                std::size_t level = 0) {
  for (auto child : ((current.get())->*F)()) {
    // Note that we're not invoking the callback for the root.
    callback(child, level);
    dfs<T, F>(child, callback, level + 1);
  }
}

/**
 * Converts an UTC date and time value into localtime and prints the result to
 * a string.
 * @param [in] time Date and time in UTC.
 * @return @a time as a human readable string.
 */
std::string time_to_str(const std::time_t& time);

std::array<uint8_t, 16> generate_uuid();

}   // namespace keepass
