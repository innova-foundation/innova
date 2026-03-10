// Copyright (c) 2019-2026 The Innova developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef ED25519_ZK_H
#define ED25519_ZK_H

#include <vector>
#include <stdint.h>



#ifndef INN_CURVETREE_H
static const size_t ED25519_SCALAR_SIZE = 32;
static const size_t ED25519_POINT_SIZE = 32;
#endif



bool Ed25519ScalarAdd(const std::vector<unsigned char>& a,
                      const std::vector<unsigned char>& b,
                      std::vector<unsigned char>& resultOut);

bool Ed25519ScalarMul(const std::vector<unsigned char>& a,
                      const std::vector<unsigned char>& b,
                      std::vector<unsigned char>& resultOut);

bool Ed25519ScalarInv(const std::vector<unsigned char>& a,
                      std::vector<unsigned char>& resultOut);

bool Ed25519ScalarNeg(const std::vector<unsigned char>& a,
                      std::vector<unsigned char>& resultOut);

bool Ed25519ScalarReduce(const std::vector<unsigned char>& input,
                         std::vector<unsigned char>& resultOut);

bool Ed25519ScalarIsZero(const std::vector<unsigned char>& a);




bool Ed25519ScalarMult(const std::vector<unsigned char>& scalar,
                       const std::vector<unsigned char>& point,
                       std::vector<unsigned char>& resultOut);

bool Ed25519BasePointMult(const std::vector<unsigned char>& scalar,
                          std::vector<unsigned char>& resultOut);

bool Ed25519PointAdd(const std::vector<unsigned char>& p1,
                     const std::vector<unsigned char>& p2,
                     std::vector<unsigned char>& resultOut);

bool Ed25519PointNeg(const std::vector<unsigned char>& point,
                     std::vector<unsigned char>& resultOut);

bool Ed25519DoubleScalarMult(const std::vector<unsigned char>& s1,
                              const std::vector<unsigned char>& p1,
                              const std::vector<unsigned char>& s2,
                              std::vector<unsigned char>& resultOut);

bool Ed25519PointIsValid(const std::vector<unsigned char>& point);

bool Ed25519PointIsIdentity(const std::vector<unsigned char>& point);




bool Ed25519HashToPoint(const std::string& label,
                        std::vector<unsigned char>& resultOut);

bool Ed25519HashToPointFromBytes(const unsigned char* data,
                                  size_t len,
                                  std::vector<unsigned char>& resultOut);




bool Ed25519PedersenCommit(const std::vector<unsigned char>& value,
                            const std::vector<unsigned char>& blind,
                            const std::vector<unsigned char>& H,
                            std::vector<unsigned char>& commitOut);




void Ed25519GetBasepoint(std::vector<unsigned char>& pointOut);

void Ed25519GetIdentity(std::vector<unsigned char>& pointOut);


#endif // ED25519_ZK_H
