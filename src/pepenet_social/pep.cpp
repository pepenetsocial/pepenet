#include "pep.h"
namespace pepenet_social {
  ibool pep_args::loadFromJson()
  {
    if (!m_json.HasMember("msg"))
    {
      return ibool{ false, std::string("json field msg is required!") };
    }
    else
    {
      m_msg = m_json["msg"].GetString();
    }
    if (m_json.HasMember("pseudonym"))
    {
      m_pseudonym = m_json["pseudonym"].GetString();
    }
    if (m_json.HasMember("sk_seed"))
    {
      if (!m_json.HasMember("post_pk"))
      {
        return ibool{ false, std::string("json field post_pk is required when sk_seed is defined!") };
      }
      m_sk_seed = m_json["sk_seed"].GetString();
    }
    if (m_json.HasMember("post_pk"))
    {
      m_post_pk = m_json["post_pk"].GetBool();
      if (!m_json.HasMember("sk_seed"))
      {
        return ibool{ false, std::string("json field sk_seed is required when post_pk is defined!") };
      }
    }
    if (m_json.HasMember("tx_ref"))
    {
      std::string tx_ref_hex = m_json["tx_ref"].GetString();
      crypto::hash tx_ref_parsed;
      if (!epee::string_tools::hex_to_pod(tx_ref_hex, tx_ref_parsed))
      {
        return ibool{ false, std::string("unable to parse tx_ref from json!")};
      }
      m_tx_ref = tx_ref_parsed;
    }
    if (m_json.HasMember("pepetag"))
    {
      m_pepetag = m_json["pepetag"].GetString();
    }
    if (m_json.HasMember("donation_address"))
    {
      m_donation_address = m_json["donation_address"].GetString();
    }
    m_valid_args = true;
    
    return ibool{ true, INFO_NULLOPT };
  }

  ibool pep_args::validate()
  {
    if (m_valid_args)
    {
      return ibool{ true, INFO_NULLOPT };
    }
    if (m_msg.empty())
    {
      return { false, std::string("msg must be defined in pep_args!") };
    }
    if (m_post_pk.has_value() != m_sk_seed.has_value())
    {
      return { false, std::string("post_pk and sk_seed must both be defined in pep_args!") };
    }
    return ibool{ true, INFO_NULLOPT };
  }

}