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

#include <fstream>

#include <gtest/gtest.h>

#include "kdb.hh"
#include "key.hh"

using namespace keepass;

namespace {

std::string GetTestPath(const std::string& name) {
  return "./test/data/" + name;
}

std::string GetTestJson(const std::string& name) {
  std::ifstream file(GetTestPath(name));
  std::string file_str((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());

  // Compact the JSON by removing all white space not present in string
  // literals.
  char quote = '\0';
  std::string json;
  for (char c : file_str) {
    if (quote != '\0') {
      if (c == quote)
        quote = '\0';

      json.push_back(c);
    } else if (c == '"' || c == '\'') {
      quote = c;
      json.push_back(c);
    } else if (!std::isspace<char>(c, std::locale::classic())) {
      json.push_back(c);
    }
  }

  return json;
}

}   // namespace

TEST(KdbTest, CorrectPassword) {
  Key key("password");

  KdbFile file;
  EXPECT_NO_THROW(file.Import(GetTestPath("groups-1-empty-pw-aes.kdb"), key));
}

TEST(KdbTest, InvalidPassword) {
  Key key("wrong_password");

  KdbFile file;
  EXPECT_THROW(file.Import(GetTestPath("groups-1-empty-pw-aes.kdb"), key),
               std::runtime_error);
}

TEST(KdbTest, ImportGroups1) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-1-empty-pw-aes.kdb"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-1-empty-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-1-random_entry-1-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-1-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-1-random_entry-2-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-1-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-1-random_entry-3-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-1-random_entry-3-pw-aes.json"));
}

TEST(KdbTest, ImportGroups2) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-2-empty-pw-aes.kdb"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-2-empty-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-2-random_entry-1-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-2-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-2-random_entry-2-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-2-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-2-random_entry-3-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-2-random_entry-3-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-2-random_entry-4-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-2-random_entry-4-pw-aes.json"));
}

TEST(KdbTest, ImportGroups3) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-3-empty-pw-aes.kdb"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-3-empty-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-3-random_entry-1-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-3-random_entry-1-pw-aes.json"));
}

TEST(KdbTest, ImportGroups4) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-4-empty-pw-aes.kdb"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-4-empty-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-4-random_entry-1-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-4-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-4-random_entry-2-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-4-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-4-random_entry-3-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-4-random_entry-3-pw-aes.json"));
}

TEST(KdbTest, ImportGroups5) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-5-empty-pw-aes.kdb"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-5-empty-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-5-random_entry-1-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-5-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-5-random_entry-2-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-5-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-5-random_entry-3-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-5-random_entry-3-pw-aes.json"));
}

TEST(KdbTest, ImportGroups6) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-6-empty-pw-aes.kdb"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-6-empty-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-6-random_entry-1-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-6-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-6-random_entry-2-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-6-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-6-random_entry-3-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-6-random_entry-3-pw-aes.json"));
}

TEST(KdbTest, ImportGroups7) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-7-empty-pw-aes.kdb"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-7-empty-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-7-random_entry-1-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-7-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-7-random_entry-2-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-7-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-7-random_entry-3-pw-aes.kdb"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-7-random_entry-3-pw-aes.json"));
}

TEST(KdbTest, ImportGroups8) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-8-empty-pw-aes.kdb"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-8-empty-pw-aes.json"));
}

TEST(KdbTest, ImportGroups9) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-9-default-pw-aes.kdb"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-9-default-pw-aes.json"));
}

TEST(KdbTest, ImportComplex1) {
  Key key("password");

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("complex-1-pw-aes.kdb"), key);
  });

  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("complex-1-pw-aes.json"));
}

TEST(KdbTest, ImportComplex1KeyFile) {
  Key key;
  key.SetKeyFile(GetTestPath("complex-1-key-tf.key"));

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("complex-1-key-tf.kdb"), key);
  });

  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("complex-1-key-tf.json"));
}

TEST(KdbTest, ImportComplex1KeyFileAndPassword) {
  Key key("password");
  key.SetKeyFile(GetTestPath("complex-1-key_pw-tf.key"));

  KdbFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("complex-1-key_pw-tf.kdb"), key);
  });

  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("complex-1-key_pw-tf.json"));
}
